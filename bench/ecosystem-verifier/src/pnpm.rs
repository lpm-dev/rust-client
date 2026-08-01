use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use serde::Deserialize;

use crate::canonical::{
    CANONICAL_SCHEMA_VERSION, CanonicalGraph, Capabilities, DependencyEdge, DependencyKind,
    Diagnostic, DiagnosticSeverity, GraphTelemetry, ImporterGraph, Manager, PackageInstance,
    PackageSource, PlatformConstraints, TargetKind, TargetReference,
};
use crate::error::{Result, VerifierError};
use crate::workspace::{
    canonical_workspace, discover_workspace_packages, normalize_lock_path, normalize_relative_path,
};

const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";

#[derive(Debug, Deserialize)]
struct PnpmLockfile {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: serde_yaml::Value,
    #[serde(default)]
    importers: BTreeMap<String, PnpmImporter>,
    #[serde(default)]
    packages: BTreeMap<String, PnpmPackage>,
    #[serde(default)]
    snapshots: BTreeMap<String, PnpmSnapshot>,
}

#[derive(Debug, Default, Deserialize)]
struct PnpmImporter {
    #[serde(default)]
    dependencies: BTreeMap<String, serde_yaml::Value>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, serde_yaml::Value>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct PnpmPackage {
    #[serde(default)]
    resolution: Option<PnpmResolution>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    os: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    cpu: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    libc: Vec<String>,
    #[serde(default)]
    dev: Option<bool>,
    #[serde(default)]
    optional: Option<bool>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependenciesMeta")]
    peer_dependencies_meta: BTreeMap<String, PnpmPeerMeta>,
}

#[derive(Debug, Default, Deserialize)]
struct PnpmPeerMeta {
    #[serde(default)]
    optional: bool,
}

#[derive(Debug, Default, Deserialize)]
struct PnpmResolution {
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    tarball: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PnpmSnapshot {
    #[serde(default)]
    dependencies: BTreeMap<String, serde_yaml::Value>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug)]
struct ParsedInstance<'a> {
    id: &'a str,
    name: String,
    version: String,
    peer_bindings: BTreeMap<String, TargetReference>,
    patch_hash: Option<String>,
}

pub fn normalize(workspace: &Path) -> Result<CanonicalGraph> {
    let workspace = canonical_workspace(workspace)?;
    let lockfile_path = workspace.join("pnpm-lock.yaml");
    if !lockfile_path.is_file() {
        return Err(VerifierError::NoPnpmLockfile {
            path: lockfile_path,
        });
    }
    let bytes = std::fs::read(&lockfile_path).map_err(|source| VerifierError::Read {
        path: lockfile_path.clone(),
        source,
    })?;
    let lockfile: PnpmLockfile =
        serde_yaml::from_slice(&bytes).map_err(|source| VerifierError::YamlRead {
            path: lockfile_path.clone(),
            source,
        })?;
    let version = yaml_scalar(&lockfile.lockfile_version);
    if !version.starts_with('9') {
        return Err(VerifierError::UnsupportedPnpmLockfile {
            path: lockfile_path,
            version,
        });
    }
    let workspace_packages = discover_workspace_packages(&workspace)?;
    normalize_parsed(&workspace, version, lockfile, &workspace_packages)
}

fn normalize_parsed(
    workspace: &Path,
    version: String,
    lockfile: PnpmLockfile,
    workspace_packages: &BTreeMap<String, String>,
) -> Result<CanonicalGraph> {
    let workspace_links = collect_workspace_links(&lockfile.importers);
    let mut graph = CanonicalGraph {
        schema_version: CANONICAL_SCHEMA_VERSION,
        manager: Manager {
            name: "pnpm".into(),
            lockfile_version: version,
        },
        workspace: workspace.display().to_string(),
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
        importers: BTreeMap::new(),
        diagnostics: Vec::new(),
        telemetry: GraphTelemetry::default(),
    };

    for (raw_path, importer) in &lockfile.importers {
        let importer_path = normalized_importer_path(raw_path);
        let direct_dependencies = importer_edges(
            &importer_path,
            importer,
            &workspace_links,
            workspace_packages,
        );
        let (packages, mut diagnostics) = importer_closure(
            &importer_path,
            &direct_dependencies,
            &lockfile.packages,
            &lockfile.snapshots,
            &workspace_links,
            workspace_packages,
        )?;
        graph.diagnostics.append(&mut diagnostics);
        graph.importers.insert(
            importer_path.clone(),
            ImporterGraph {
                path: importer_path,
                direct_dependencies,
                packages,
            },
        );
    }
    graph.finalize();
    Ok(graph)
}

fn collect_workspace_links(
    importers: &BTreeMap<String, PnpmImporter>,
) -> BTreeMap<(String, String), String> {
    let mut links = BTreeMap::new();
    for (raw_importer, importer) in importers {
        let importer_path = normalized_importer_path(raw_importer);
        for dependencies in [
            &importer.dependencies,
            &importer.dev_dependencies,
            &importer.optional_dependencies,
        ] {
            for (local_name, value) in dependencies {
                if let Some((_, resolved)) = importer_dependency(value)
                    && let Some(raw_path) = resolved.strip_prefix("link:")
                {
                    let path = normalize_relative_path(&importer_path, raw_path);
                    links.insert((local_name.clone(), path.replace('/', "+")), path);
                }
            }
        }
    }
    links
}

fn importer_edges(
    importer_path: &str,
    importer: &PnpmImporter,
    workspace_links: &BTreeMap<(String, String), String>,
    workspace_packages: &BTreeMap<String, String>,
) -> Vec<DependencyEdge> {
    let capacity = importer.dependencies.len()
        + importer.dev_dependencies.len()
        + importer.optional_dependencies.len();
    let mut edges = Vec::with_capacity(capacity);
    append_importer_edges(
        &mut edges,
        importer_path,
        &importer.dependencies,
        DependencyKind::Production,
        workspace_links,
        workspace_packages,
    );
    append_importer_edges(
        &mut edges,
        importer_path,
        &importer.dev_dependencies,
        DependencyKind::Development,
        workspace_links,
        workspace_packages,
    );
    append_importer_edges(
        &mut edges,
        importer_path,
        &importer.optional_dependencies,
        DependencyKind::Optional,
        workspace_links,
        workspace_packages,
    );
    edges
}

fn append_importer_edges(
    edges: &mut Vec<DependencyEdge>,
    importer_path: &str,
    dependencies: &BTreeMap<String, serde_yaml::Value>,
    kind: DependencyKind,
    workspace_links: &BTreeMap<(String, String), String>,
    workspace_packages: &BTreeMap<String, String>,
) {
    for (local_name, value) in dependencies {
        let Some((specifier, resolved)) = importer_dependency(value) else {
            edges.push(DependencyEdge {
                kind,
                local_name: local_name.clone(),
                specifier: None,
                target: TargetReference::unresolved(Some(local_name.clone()), None),
            });
            continue;
        };
        edges.push(DependencyEdge {
            kind,
            local_name: local_name.clone(),
            specifier,
            target: resolve_importer_reference(
                importer_path,
                local_name,
                &resolved,
                workspace_links,
                workspace_packages,
            ),
        });
    }
}

fn resolve_importer_reference(
    importer_path: &str,
    local_name: &str,
    raw: &str,
    workspace_links: &BTreeMap<(String, String), String>,
    workspace_packages: &BTreeMap<String, String>,
) -> TargetReference {
    if let Some(path) = raw.strip_prefix("link:") {
        return TargetReference::workspace(
            Some(local_name.into()),
            normalize_relative_path(importer_path, path),
        );
    }
    resolve_reference(local_name, raw, workspace_links, workspace_packages)
}

fn importer_dependency(value: &serde_yaml::Value) -> Option<(Option<String>, String)> {
    match value {
        serde_yaml::Value::String(resolved) => Some((None, resolved.clone())),
        serde_yaml::Value::Number(resolved) => Some((None, resolved.to_string())),
        serde_yaml::Value::Mapping(mapping) => {
            let specifier = mapping
                .get(serde_yaml::Value::String("specifier".into()))
                .and_then(yaml_value_string);
            let resolved = mapping
                .get(serde_yaml::Value::String("version".into()))
                .and_then(yaml_value_string)?;
            Some((specifier, resolved))
        }
        _ => None,
    }
}

fn importer_closure(
    importer_path: &str,
    direct_dependencies: &[DependencyEdge],
    metadata: &BTreeMap<String, PnpmPackage>,
    snapshots: &BTreeMap<String, PnpmSnapshot>,
    workspace_links: &BTreeMap<(String, String), String>,
    workspace_packages: &BTreeMap<String, String>,
) -> Result<(BTreeMap<String, PackageInstance>, Vec<Diagnostic>)> {
    let mut packages = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let mut pending: VecDeque<String> = direct_dependencies
        .iter()
        .filter_map(|edge| edge.target.instance.clone())
        .collect();
    let mut visited = BTreeSet::new();

    while let Some(instance_id) = pending.pop_front() {
        if !visited.insert(instance_id.clone()) {
            continue;
        }
        let Some(snapshot) = snapshots.get(&instance_id) else {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "pnpm_snapshot_missing".into(),
                message: format!("resolved package instance {instance_id} has no snapshot"),
                importer: Some(importer_path.into()),
                subject: Some(instance_id),
            });
            continue;
        };
        let mut parsed = parse_instance(&instance_id, workspace_links)?;
        let metadata_key = format!("{}@{}", parsed.name, parsed.version);
        let package_metadata = metadata.get(&metadata_key);
        if package_metadata.is_none() {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Warning,
                code: "pnpm_package_metadata_missing".into(),
                message: format!("package instance {instance_id} has no packages metadata entry"),
                importer: Some(importer_path.into()),
                subject: Some(instance_id.clone()),
            });
        }
        let mut dependencies = snapshot_edges(snapshot, workspace_links, workspace_packages);
        for edge in &dependencies {
            if let Some(target) = &edge.target.instance {
                pending.push_back(target.clone());
            }
        }
        let default_metadata = PnpmPackage::default();
        let package_metadata = package_metadata.unwrap_or(&default_metadata);
        for edge in &dependencies {
            if package_metadata
                .peer_dependencies
                .contains_key(&edge.local_name)
            {
                parsed
                    .peer_bindings
                    .entry(edge.local_name.clone())
                    .or_insert_with(|| edge.target.clone());
            }
        }
        parsed
            .peer_bindings
            .retain(|name, _| package_metadata.peer_dependencies.contains_key(name));
        dependencies.retain(|edge| {
            !package_metadata
                .peer_dependencies
                .contains_key(&edge.local_name)
        });
        dependencies.sort();
        let source = pnpm_source(package_metadata);
        let optional_peers = package_metadata
            .peer_dependencies_meta
            .iter()
            .filter_map(|(name, meta)| meta.optional.then_some(name.clone()))
            .collect();
        packages.insert(
            instance_id.clone(),
            PackageInstance {
                id: parsed.id.to_string(),
                name: parsed.name,
                version: parsed.version,
                source,
                optional: package_metadata.optional,
                dev: package_metadata.dev,
                platform: PlatformConstraints {
                    os: sorted(package_metadata.os.clone()),
                    cpu: sorted(package_metadata.cpu.clone()),
                    libc: sorted(package_metadata.libc.clone()),
                },
                dependencies,
                peer_bindings: parsed.peer_bindings,
                declared_peers: package_metadata.peer_dependencies.clone(),
                optional_peers,
                patch_hash: parsed.patch_hash,
            },
        );
    }

    Ok((packages, diagnostics))
}

fn snapshot_edges(
    snapshot: &PnpmSnapshot,
    workspace_links: &BTreeMap<(String, String), String>,
    workspace_packages: &BTreeMap<String, String>,
) -> Vec<DependencyEdge> {
    let mut edges =
        Vec::with_capacity(snapshot.dependencies.len() + snapshot.optional_dependencies.len());
    append_snapshot_edges(
        &mut edges,
        &snapshot.dependencies,
        DependencyKind::Production,
        workspace_links,
        workspace_packages,
    );
    append_snapshot_edges(
        &mut edges,
        &snapshot.optional_dependencies,
        DependencyKind::Optional,
        workspace_links,
        workspace_packages,
    );
    edges
}

fn append_snapshot_edges(
    edges: &mut Vec<DependencyEdge>,
    dependencies: &BTreeMap<String, serde_yaml::Value>,
    kind: DependencyKind,
    workspace_links: &BTreeMap<(String, String), String>,
    workspace_packages: &BTreeMap<String, String>,
) {
    for (local_name, value) in dependencies {
        let Some(resolved) = yaml_value_string(value) else {
            edges.push(DependencyEdge {
                kind,
                local_name: local_name.clone(),
                specifier: None,
                target: TargetReference::unresolved(Some(local_name.clone()), None),
            });
            continue;
        };
        edges.push(DependencyEdge {
            kind,
            local_name: local_name.clone(),
            specifier: None,
            target: resolve_reference(local_name, &resolved, workspace_links, workspace_packages),
        });
    }
}

fn resolve_reference(
    local_name: &str,
    raw: &str,
    workspace_links: &BTreeMap<(String, String), String>,
    workspace_packages: &BTreeMap<String, String>,
) -> TargetReference {
    if let Some(path) = raw.strip_prefix("link:") {
        return TargetReference::workspace(Some(local_name.into()), normalize_lock_path(path));
    }
    let base = raw.split('(').next().unwrap_or(raw);
    if let Some(path) = base.strip_prefix("file:") {
        return external_file_reference(path, None, workspace_packages);
    }
    if base.starts_with("http:") || base.starts_with("https:") {
        return TargetReference {
            kind: TargetKind::External,
            name: None,
            version: None,
            instance: None,
            path: Some(base.into()),
        };
    }
    let (name, version) = match split_name_version(base) {
        Some((name, version)) => (name.to_string(), version.to_string()),
        None => (local_name.to_string(), base.to_string()),
    };
    if let Some(path) = version.strip_prefix("file:") {
        return external_file_reference(path, Some(name), workspace_packages);
    }
    if let Some(path) = workspace_links.get(&(name.clone(), version.clone())) {
        return TargetReference::workspace(Some(name), path.clone());
    }
    let instance = if name == local_name {
        format!("{local_name}@{raw}")
    } else {
        raw.to_string()
    };
    TargetReference::package(name, version, instance)
}

fn external_file_reference(
    path: &str,
    encoded_name: Option<String>,
    workspace_packages: &BTreeMap<String, String>,
) -> TargetReference {
    let path = normalize_lock_path(path);
    let manifest_name = workspace_packages
        .iter()
        .find_map(|(name, package_path)| (package_path == &path).then_some(name.clone()));
    TargetReference {
        kind: TargetKind::External,
        name: manifest_name.or(encoded_name),
        version: None,
        instance: None,
        path: Some(format!("file:{path}")),
    }
}

fn parse_instance<'a>(
    instance: &'a str,
    workspace_links: &BTreeMap<(String, String), String>,
) -> Result<ParsedInstance<'a>> {
    let base = instance.split('(').next().unwrap_or(instance);
    let Some((name, version)) = split_name_version(base) else {
        return Err(VerifierError::InvalidPnpmReference {
            reference: instance.into(),
            reason: "expected name@version".into(),
        });
    };
    let mut peer_bindings = BTreeMap::new();
    let mut patch_hash = None;
    for context in parenthesized_contexts(&instance[base.len()..])? {
        if let Some(hash) = context.strip_prefix("patch_hash=") {
            patch_hash = Some(hash.into());
            continue;
        }
        if is_hashed_peer_context(context) {
            continue;
        }
        let peer_base = context.split('(').next().unwrap_or(context);
        let Some((peer_name, peer_version)) = split_name_version(peer_base) else {
            return Err(VerifierError::InvalidPnpmReference {
                reference: instance.into(),
                reason: format!("invalid peer context {context:?}"),
            });
        };
        let target = if let Some(path) =
            workspace_links.get(&(peer_name.to_string(), peer_version.to_string()))
        {
            TargetReference::workspace(Some(peer_name.into()), path.clone())
        } else {
            TargetReference::package(peer_name, peer_version, context.to_owned())
        };
        peer_bindings.insert(peer_name.into(), target);
    }
    Ok(ParsedInstance {
        id: instance,
        name: name.into(),
        version: version.into(),
        peer_bindings,
        patch_hash,
    })
}

fn parenthesized_contexts(mut suffix: &str) -> Result<Vec<&str>> {
    let mut contexts = Vec::new();
    while !suffix.is_empty() {
        if !suffix.starts_with('(') {
            return Err(VerifierError::InvalidPnpmReference {
                reference: suffix.into(),
                reason: "peer context must begin with '('".into(),
            });
        }
        let mut depth = 0_usize;
        let mut end = None;
        for (index, character) in suffix.char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(index);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            return Err(VerifierError::InvalidPnpmReference {
                reference: suffix.into(),
                reason: "unterminated peer context".into(),
            });
        };
        contexts.push(&suffix[1..end]);
        suffix = &suffix[end + 1..];
    }
    Ok(contexts)
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

fn is_hashed_peer_context(context: &str) -> bool {
    context.len() == 32 && context.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn pnpm_source(package: &PnpmPackage) -> PackageSource {
    let resolution = package.resolution.as_ref();
    let tarball = resolution.and_then(|value| value.tarball.clone());
    let (kind, locator) = match tarball {
        Some(url)
            if url.trim_end_matches('/') == DEFAULT_NPM_REGISTRY
                || url.starts_with("https://registry.npmjs.org/") =>
        {
            ("registry", DEFAULT_NPM_REGISTRY.to_string())
        }
        Some(url) => ("tarball", url),
        None => ("registry", DEFAULT_NPM_REGISTRY.to_string()),
    };
    PackageSource {
        kind: Some(kind.into()),
        locator: Some(locator),
        integrity: resolution.and_then(|value| value.integrity.clone()),
    }
}

fn normalized_importer_path(path: &str) -> String {
    let normalized = normalize_lock_path(path);
    if normalized.is_empty() {
        ".".into()
    } else {
        normalized
    }
}

fn yaml_scalar(value: &serde_yaml::Value) -> String {
    yaml_value_string(value).unwrap_or_else(|| "unknown".into())
}

fn yaml_value_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(value) => Some(value.clone()),
        serde_yaml::Value::Number(value) => Some(value.to_string()),
        serde_yaml::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn deserialize_string_list<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_yaml::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_yaml::Value::Null) => Ok(Vec::new()),
        Some(serde_yaml::Value::String(value)) => Ok(vec![value]),
        Some(serde_yaml::Value::Sequence(values)) => values
            .into_iter()
            .map(|value| {
                yaml_value_string(&value)
                    .ok_or_else(|| serde::de::Error::custom("expected a string list entry"))
            })
            .collect(),
        Some(_) => Err(serde::de::Error::custom(
            "expected a string or a sequence of strings",
        )),
    }
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKFILE: &str = r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      app:
        specifier: workspace:*
        version: link:packages/app
      react:
        specifier: ^19.0.0
        version: 19.1.0
      renderer:
        specifier: npm:react-dom@^19.0.0
        version: react-dom@19.1.0(react@19.1.0)(ms@2.1.3)
  packages/app:
    dependencies:
      react:
        specifier: ^19.0.0
        version: 19.1.0
      vite:
        specifier: workspace:*
        version: link:../vite
  packages/vite: {}
packages:
  react@19.1.0:
    resolution: {integrity: sha512-react}
  react-dom@19.1.0:
    resolution: {integrity: sha512-dom}
    peerDependencies:
      react: ^19.0.0
snapshots:
  react@19.1.0: {}
  react-dom@19.1.0(react@19.1.0)(ms@2.1.3):
    dependencies:
      react: 19.1.0
      scheduler: 0.26.0
  scheduler@0.26.0: {}
"#;

    #[test]
    fn v9_normalization_preserves_importers_aliases_peers_and_closures() {
        let parsed: PnpmLockfile = serde_yaml::from_str(LOCKFILE).expect("parse fixture");
        let graph = normalize_parsed(
            Path::new("/fixture"),
            "9.0".into(),
            parsed,
            &BTreeMap::new(),
        )
        .expect("normalize fixture");

        let root = graph.importers.get(".").expect("root importer");
        assert_eq!(root.packages.len(), 3);
        let alias = root
            .direct_dependencies
            .iter()
            .find(|edge| edge.local_name == "renderer")
            .expect("alias edge");
        assert_eq!(alias.target.name.as_deref(), Some("react-dom"));
        assert_eq!(
            alias.target.instance.as_deref(),
            Some("react-dom@19.1.0(react@19.1.0)(ms@2.1.3)")
        );
        let renderer = root
            .packages
            .get("react-dom@19.1.0(react@19.1.0)(ms@2.1.3)")
            .expect("peer-context package");
        assert_eq!(
            renderer
                .peer_bindings
                .get("react")
                .and_then(|target| target.version.as_deref()),
            Some("19.1.0")
        );
        assert_eq!(
            renderer
                .peer_bindings
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["react"],
            "transitive peer contexts in a pnpm snapshot key are not direct peer bindings of the package"
        );
        assert_eq!(renderer.declared_peers["react"], "^19.0.0");
        assert_eq!(
            renderer
                .dependencies
                .iter()
                .map(|edge| edge.local_name.as_str())
                .collect::<Vec<_>>(),
            ["scheduler"],
            "pnpm snapshots encode resolved peers in dependencies, but the canonical graph carries them only in peer_bindings"
        );
        assert_eq!(graph.telemetry.importer_count, 3);
        assert_eq!(graph.telemetry.package_instance_occurrences, 4);
        let nested_vite = graph.importers["packages/app"]
            .direct_dependencies
            .iter()
            .find(|edge| edge.local_name == "vite")
            .expect("nested workspace edge");
        assert_eq!(nested_vite.target.path.as_deref(), Some("packages/vite"));
    }

    #[test]
    fn patch_context_is_not_misreported_as_a_peer_binding() {
        let links = BTreeMap::new();
        let parsed = parse_instance("chokidar@3.6.0(patch_hash=abc123)(fsevents@2.3.3)", &links)
            .expect("parse patched instance");

        assert_eq!(parsed.patch_hash.as_deref(), Some("abc123"));
        assert_eq!(parsed.peer_bindings.len(), 1);
        assert!(parsed.peer_bindings.contains_key("fsevents"));
    }

    #[test]
    fn nested_peer_contexts_preserve_only_top_level_peer_bindings() {
        let links = BTreeMap::new();
        let eslint_plugin = "@typescript-eslint/eslint-plugin@8.65.0(@typescript-eslint/parser@8.65.0(eslint@10.7.0(jiti@2.7.0)(supports-color@10.2.2))(typescript@6.0.3))(eslint@10.7.0(jiti@2.7.0)(supports-color@10.2.2))(typescript@6.0.3)";
        let instance = format!("plugin@1.0.0({eslint_plugin})(vitest@4.1.10)");

        let parsed = parse_instance(&instance, &links).expect("parse nested peer contexts");

        assert_eq!(
            parsed
                .peer_bindings
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["@typescript-eslint/eslint-plugin", "vitest"]
        );
        let eslint = &parsed.peer_bindings["@typescript-eslint/eslint-plugin"];
        assert_eq!(eslint.version.as_deref(), Some("8.65.0"));
        assert_eq!(eslint.instance.as_deref(), Some(eslint_plugin));
        assert_eq!(
            parsed.peer_bindings["vitest"].version.as_deref(),
            Some("4.1.10")
        );
    }

    #[test]
    fn hashed_peer_context_uses_snapshot_dependencies_for_peer_bindings() {
        const PEER_HASH: &str = "3b1a25b0995775fe57cda10016bb2bdd";
        let lockfile = format!(
            r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: ^19.0.0
        version: 19.1.0({PEER_HASH})
packages:
  react@19.1.0:
    resolution: {{integrity: sha512-react}}
  react-dom@19.1.0:
    resolution: {{integrity: sha512-dom}}
    peerDependencies:
      react: ^19.0.0
snapshots:
  react@19.1.0: {{}}
  react-dom@19.1.0({PEER_HASH}):
    dependencies:
      react: 19.1.0
"#
        );
        let parsed: PnpmLockfile = serde_yaml::from_str(&lockfile).expect("parse fixture");

        let graph = normalize_parsed(
            Path::new("/fixture"),
            "9.0".into(),
            parsed,
            &BTreeMap::new(),
        )
        .expect("normalize hashed peer context");

        let package = &graph.importers["."].packages[&format!("react-dom@19.1.0({PEER_HASH})")];
        assert_eq!(
            package
                .peer_bindings
                .get("react")
                .and_then(|target| target.version.as_deref()),
            Some("19.1.0")
        );
        assert!(package.dependencies.is_empty());
    }

    #[test]
    fn workspace_peer_context_resolves_to_the_importer_path() {
        let links = BTreeMap::from([(
            ("vite".into(), "packages+vite".into()),
            "packages/vite".into(),
        )]);
        let parsed = parse_instance("plugin@1.0.0(vite@packages+vite)", &links)
            .expect("parse workspace peer");

        let vite = parsed.peer_bindings.get("vite").expect("vite binding");
        assert_eq!(vite.kind, TargetKind::Workspace);
        assert_eq!(vite.path.as_deref(), Some("packages/vite"));
    }

    #[test]
    fn platform_constraints_accept_scalar_and_sequence_forms() {
        let package: PnpmPackage =
            serde_yaml::from_str("os: linux\ncpu: [arm64, x64]\nlibc: glibc\n")
                .expect("parse mixed platform constraint forms");

        assert_eq!(package.os, ["linux"]);
        assert_eq!(package.cpu, ["arm64", "x64"]);
        assert_eq!(package.libc, ["glibc"]);
    }

    #[test]
    fn named_file_reference_is_an_external_boundary_with_manifest_identity() {
        let workspace_links = BTreeMap::new();
        let workspace_packages =
            BTreeMap::from([("@fixture/target".into(), "fixtures/target".into())]);

        let target = resolve_reference(
            "aliased-target",
            "@fixture/target@file:fixtures/target",
            &workspace_links,
            &workspace_packages,
        );

        assert_eq!(target.kind, TargetKind::External);
        assert_eq!(target.name.as_deref(), Some("@fixture/target"));
        assert_eq!(target.path.as_deref(), Some("file:fixtures/target"));
        assert!(target.instance.is_none());
    }
}
