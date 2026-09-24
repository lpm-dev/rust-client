use super::*;
use lpm_resolver::NpmVersion;
use lpm_resolver::ranges::NpmRange;
use std::collections::BTreeMap;

pub(in crate::commands::install) struct PeerReplayContext<'a> {
    pub client: &'a RegistryClient,
    pub route_table: &'a RouteTable,
    pub offline: bool,
    pub project_dir: &'a Path,
    pub lpm_root: &'a lpm_common::LpmRoot,
    pub store_version: lpm_store::StoreVersion,
}

#[derive(serde::Deserialize)]
struct PeerManifest {
    #[serde(default, rename = "peerDependencies")]
    requirements: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependenciesMeta")]
    metadata: BTreeMap<String, PeerMetadata>,
}

#[derive(serde::Deserialize)]
struct PeerMetadata {
    #[serde(default)]
    optional: bool,
}

pub(in crate::commands::install) async fn enforce_replayed_peer_dependencies(
    packages: &[InstallPackage],
    root: &lpm_workspace::PackageJson,
    context: PeerReplayContext<'_>,
) -> Result<(), LpmError> {
    let rules = match root.lpm.as_ref() {
        Some(config) => CompiledPeerRules::compile(
            &config.peer_dependency_rules.ignore_missing,
            &config.peer_dependency_rules.allowed_versions,
            &config.peer_dependency_rules.allow_any,
        )
        .map_err(|error| LpmError::Script(format!("invalid lpm.peerDependencyRules: {error}")))?,
        None => CompiledPeerRules::default(),
    };
    let by_instance: HashMap<_, _> = packages
        .iter()
        .filter_map(|package| package.instance_id.map(|id| (id, package)))
        .collect();
    let store = PackageStore::from_root(context.lpm_root);
    let store_v2 = context.store_version.uses_virtual_store().then(|| {
        lpm_store::v2::Store::from_lpm_root_for_version(context.lpm_root, context.store_version)
    });
    let mut tag_metadata = HashMap::new();
    let mut warnings = Vec::new();
    for consumer in packages {
        let source = consumer
            .source_kind()
            .map_err(|error| LpmError::PeerDependency(error.to_string()))?;
        let source_backed = !matches!(source, lpm_lockfile::Source::Registry { .. });
        let directory = match (&store_v2, source) {
            (_, lpm_lockfile::Source::Directory { .. } | lpm_lockfile::Source::Link { .. })
            | (None, _) => consumer.store_path_or_err(&store, context.project_dir, None)?,
            (Some(store), _) => {
                let integrity = consumer.integrity.as_deref().ok_or_else(|| {
                    LpmError::PeerDependency(format!(
                        "cannot validate peers for {}@{} without package integrity",
                        consumer.name, consumer.version
                    ))
                })?;
                store.paths().object_dir(integrity)?
            }
        };
        let path = directory.join("package.json");
        let invalid = |error: String| {
            LpmError::PeerDependency(format!(
                "cannot validate peers from {}: {error}",
                path.display()
            ))
        };
        let bytes = lpm_common::read_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|error| invalid(error.to_string()))?;
        let bytes = lpm_common::strip_utf8_bom_bytes(&bytes);
        let manifest: PeerManifest =
            serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
        let source_specs = if source_backed {
            let value =
                serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
            source_resolution::source_dep_specs_from_value(&directory, &value)?
                .into_iter()
                .filter(|spec| spec.role == SourceDepRole::Peer)
                .map(|spec| (spec.local_name.clone(), spec))
                .collect::<HashMap<_, _>>()
        } else {
            HashMap::new()
        };
        for (local_name, raw_spec) in manifest.requirements {
            let optional = manifest
                .metadata
                .get(&local_name)
                .is_some_and(|entry| entry.optional);
            let source_spec = source_specs.get(&local_name);
            let spec = source_spec.map_or(raw_spec.as_str(), |spec| spec.raw_spec.as_str());
            let normalized = lpm_resolver::normalize_jsr_dependency(&local_name, spec)
                .map_err(|error| invalid(error.to_string()))?;
            let spec = normalized.as_deref().unwrap_or(spec);
            let alias = lpm_resolver::ranges::parse_npm_alias(spec);
            let (target_name, range_text) =
                alias.as_ref().map_or((local_name.as_str(), spec), |alias| {
                    (alias.target.as_str(), alias.range.as_str())
                });
            let parsed = match source_spec {
                Some(spec) => source_resolution::local_source_peer_range(spec),
                None => NpmRange::parse_registry_spec(range_text).map(Some),
            };
            let range = match parsed {
                Ok(range) => range,
                Err(_) if optional => continue,
                Err(error) => return Err(invalid(error)),
            };
            let source_identity_only = source_spec.is_some_and(|spec| {
                matches!(spec.kind, DepKind::FileDir | DepKind::Link | DepKind::Git)
            });
            let provider = consumer
                .peer_targets
                .get(&local_name)
                .and_then(|id| by_instance.get(id).copied())
                .filter(|provider| source_identity_only || provider.name == target_name);
            if let Some(provider) = provider {
                if source_spec.is_some_and(|spec| !matches!(spec.kind, DepKind::Registry))
                    && !source_peer_matches(
                        spec,
                        target_name,
                        &directory,
                        &provider.source,
                        context.project_dir,
                    )?
                {
                    return Err(invalid(format!(
                        "peer {local_name} has a locked provider from a different source than {spec}"
                    )));
                }
                let version = NpmVersion::parse(&provider.version).ok();
                if rules.allow_any_matches(&local_name)
                    || version.as_ref().is_some_and(|version| {
                        NpmVersion::parse(&consumer.version).is_ok_and(|consumer_version| {
                            rules.allowed_versions_satisfies(
                                &consumer.name,
                                &consumer_version,
                                &local_name,
                                version,
                            )
                        })
                    })
                {
                    continue;
                }
                let tagged_version = if let Some(tag) = range.as_ref().and_then(NpmRange::dist_tag)
                {
                    if !tag_metadata.contains_key(target_name) {
                        let route = context.route_table.route_for_package(target_name);
                        let metadata = if context.offline {
                            context.client.cached_package_metadata(target_name, &route).await
                                .ok_or_else(|| invalid(format!(
                                    "strict-peer-dependencies cannot validate peer {local_name} tag `{tag}` offline: fresh registry metadata is unavailable"
                                )))?
                        } else if target_name.starts_with("@lpm.dev/") {
                            let name = lpm_common::PackageName::parse(target_name)
                                .map_err(|error| invalid(error.to_string()))?;
                            Arc::new(context.client.get_package_metadata(&name).await?)
                        } else {
                            Arc::new(
                                context
                                    .client
                                    .get_npm_metadata_routed(target_name, route)
                                    .await?,
                            )
                        };
                        tag_metadata.insert(target_name.to_owned(), metadata);
                    }
                    let metadata = &tag_metadata[target_name];
                    let tagged = if tag == "latest" {
                        metadata.latest_version_tag()
                    } else {
                        metadata.dist_tags.get(tag).map(String::as_str)
                    };
                    tagged.map(NpmVersion::parse).transpose().map_err(invalid)?
                } else {
                    None
                };
                if range.as_ref().is_none_or(|range| {
                    version.as_ref().is_some_and(|version| {
                        range.satisfies_with_dist_tag(version, tagged_version.as_ref())
                    })
                }) {
                    continue;
                }
            } else if optional || rules.ignore_missing_matches(&local_name) {
                continue;
            }
            warnings.push(PeerWarning {
                package: consumer.name.clone(),
                version: consumer.version.clone(),
                peer: local_name.clone(),
                target: target_name.to_owned(),
                required_range: range_text.to_owned(),
                resolved_version: provider.map(|provider| provider.version.clone()),
            });
        }
    }
    warnings.sort_by(|a, b| {
        a.package
            .cmp(&b.package)
            .then(a.version.cmp(&b.version))
            .then(a.peer.cmp(&b.peer))
    });
    match strict_peer_dependency_error(&warnings, &[]) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn source_peer_matches(
    spec: &str,
    peer_name: &str,
    consumer_dir: &Path,
    provider_source: &str,
    project_dir: &Path,
) -> Result<bool, LpmError> {
    use lpm_lockfile::Source;
    use lpm_resolver::Specifier;
    let requested =
        Specifier::parse(spec).map_err(|error| LpmError::PeerDependency(error.to_string()))?;
    let provider = Source::parse(provider_source)
        .map_err(|error| LpmError::PeerDependency(error.to_string()))?;
    match (requested, provider) {
        (
            Specifier::File { path } | Specifier::Link { path },
            Source::Directory { path: provider } | Source::Link { path: provider },
        ) => {
            Ok(consumer_dir.join(path).canonicalize()?
                == project_dir.join(provider).canonicalize()?)
        }
        (
            Specifier::Workspace(_),
            Source::Directory { path: provider } | Source::Link { path: provider },
        ) => {
            let workspace = crate::workspace_discovery_cache::discover_workspace(consumer_dir)
                .map_err(|error| LpmError::Workspace(error.to_string()))?;
            let Some(workspace) = workspace else {
                return Ok(false);
            };
            let member = workspace
                .members
                .iter()
                .find(|member| member.package.name.as_deref() == Some(peer_name))
                .map(|member| &member.path)
                .or_else(|| {
                    (workspace.root_package.name.as_deref() == Some(peer_name))
                        .then_some(&workspace.root)
                });
            match member {
                Some(member) => {
                    Ok(member.canonicalize()? == project_dir.join(provider).canonicalize()?)
                }
                None => Ok(false),
            }
        }
        (Specifier::Git { url, refspec }, Source::Git { url: provider }) => Ok(
            lockfile::locked_github_source_matches_request(&provider, &url, refspec.as_deref()),
        ),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::source_peer_matches;
    use std::path::Path;

    #[test]
    fn git_peer_replay_preserves_repository_and_pinned_commit_identity() {
        let commit = "a".repeat(40);
        let other_commit = "b".repeat(40);
        let source = format!("git+https://github.com/example/provider.git#{commit}");
        for request in [
            "github:example/provider".to_string(),
            format!("github:example/provider#{commit}"),
        ] {
            assert!(
                source_peer_matches(
                    &request,
                    "provider",
                    Path::new("."),
                    &source,
                    Path::new(".")
                )
                .unwrap()
            );
        }
        for request in [
            "github:example/other".to_string(),
            format!("github:example/provider#{other_commit}"),
        ] {
            assert!(
                !source_peer_matches(
                    &request,
                    "provider",
                    Path::new("."),
                    &source,
                    Path::new(".")
                )
                .unwrap()
            );
        }
    }
}
