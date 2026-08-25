use super::prelude::*;
use super::state::ResolveState;
use super::types::{DepBehavior, Edge, NodeId, PeerRequirement};
use super::version::is_workspace_specifier;

/// Read one version's contiguous dependency records and push child edges.
pub(super) fn enqueue_child_deps(
    parent_id: NodeId,
    parent_canonical: &CanonicalKey,
    version: &NpmVersion,
    info: &CachedPackageInfo,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    let ver_str = version.to_string();
    let selected_from_workspace = info.workspace_versions.contains(version);

    if let Some(dependencies) = info.dependencies(&ver_str) {
        for dependency in dependencies {
            let local_name = dependency.name;
            let range_str = dependency.range;
            // Bundled deps are vendored inside the parent's tarball
            // (`node_modules/<bundled>/` extracted alongside the parent's
            // own files). Skip enqueueing them as separate edges so the
            // resolver doesn't fetch a registry copy that the linker
            // might shadow over the bundled one. The extractor preserves
            // the in-tarball subtree implicitly; the resolver's job is
            // just to NOT introduce a redundant registry fetch.
            if dependency.bundled {
                tracing::debug!(
                    "skipping bundled dep {} of {}@{} — provided by parent's tarball",
                    local_name,
                    parent_canonical,
                    ver_str,
                );
                continue;
            }

            let canonical = CanonicalKey::from_dep_name(dependency.alias.unwrap_or(local_name));
            let optional = state.nodes[parent_id as usize].optional || dependency.optional;
            if optional && !state.include_optional_dependencies {
                tracing::debug!(
                    "skipping optional dep {} of {}@{} by install option",
                    local_name,
                    parent_canonical,
                    ver_str,
                );
                continue;
            }

            // Registry-published packages should
            // never declare `workspace:` deps (npm rejects at publish
            // time), but a malformed cache entry or a future regression
            // could land one here. Skip with a specific log line rather
            // than the generic "invalid range" branch so the diagnosis
            // points at the actual cause.
            if is_workspace_specifier(range_str) {
                if selected_from_workspace {
                    continue;
                }
                let detail = format!(
                    "invalid range for {local_name}@{range_str}: registry-published packages \
                     cannot declare workspace dependencies"
                );
                if optional {
                    tracing::warn!(
                        "optional dependency {local_name}@{range_str} from \
                         {parent_canonical}@{ver_str} is invalid: {detail}"
                    );
                    continue;
                }
                return Err(ResolveError::DependencyFetch {
                    package: parent_canonical.to_string(),
                    version: ver_str,
                    detail,
                });
            }

            let range = match NpmRange::parse(range_str) {
                Ok(r) => r,
                Err(e) => {
                    let detail = format!("invalid range for {local_name}@{range_str}: {e}");
                    if optional {
                        tracing::warn!(
                            "optional dependency {local_name}@{range_str} from \
                             {parent_canonical}@{ver_str} is invalid: {e}"
                        );
                        continue;
                    }
                    return Err(ResolveError::DependencyFetch {
                        package: parent_canonical.to_string(),
                        version: ver_str,
                        detail,
                    });
                }
            };

            state.task_queue.push_back(Edge {
                parent: parent_id,
                local_name: local_name.to_owned(),
                canonical,
                range,
                behavior: DepBehavior {
                    required: !optional,
                    peer: false,
                    optional,
                },
            });
            state.work_stats.child_edge_enqueued_count =
                state.work_stats.child_edge_enqueued_count.saturating_add(1);
        }
    }

    // Capture `peerDependencies` entries that are not shadowed by a regular
    // dependency on the same local name. Peers are NOT pushed onto
    // `state.task_queue` because they must NOT become `n.children` edges —
    // see the [`PeerRequirement`] doc + the v2 graph-key rationale on
    // `state.peer_requirements`.
    //
    // Same alias / workspace / range-parse defenses as the regular-deps
    // loop above; bundled-deps gate doesn't apply to peers (npm forbids
    // peerBundle interactions; no real package ships both).
    if let Some(peers) = info.peer_dependencies(&ver_str) {
        for peer in peers {
            let peer_name = peer.name;
            let peer_range_str = peer.range;

            // `workspace:` peers from a registry-published package
            // shouldn't exist (npm rejects them at publish time).
            // Skip with a specific log rather than letting
            // `NpmRange::parse` emit an opaque error.
            if is_workspace_specifier(peer_range_str) {
                if selected_from_workspace {
                    continue;
                }
                tracing::warn!(
                    "ignoring `workspace:` peer dep '{}' from {}@{} → {} \
                     (workspace: must be resolved upstream by lpm-workspace; \
                     a registry-published package should not declare it)",
                    peer_range_str,
                    parent_canonical,
                    ver_str,
                    peer_name,
                );
                if peer.optional {
                    continue;
                }
                return Err(ResolveError::DependencyFetch {
                    package: parent_canonical.to_string(),
                    version: ver_str,
                    detail: format!(
                        "invalid peer range for {peer_name}@{peer_range_str}: registry-published packages cannot declare workspace peers"
                    ),
                });
            }

            // Alias-aware canonical lookup. Mirrors the regular-deps
            // loop: a `"peer-local": "npm:target@range"` declaration
            // (rare on peers, but legal) keys the requirement on
            // `target` so the resolver consults the correct manifest.
            let canonical = CanonicalKey::from_dep_name(peer.alias.unwrap_or(peer_name));

            let range = match NpmRange::parse(peer_range_str) {
                Ok(r) => r,
                Err(e) => {
                    if !peer.optional {
                        return Err(ResolveError::DependencyFetch {
                            package: parent_canonical.to_string(),
                            version: ver_str,
                            detail: format!(
                                "invalid peer range for {peer_name}@{peer_range_str}: {e}"
                            ),
                        });
                    }
                    tracing::warn!(
                        "invalid peer range '{}' on {}@{} → {}: {e}",
                        peer_range_str,
                        parent_canonical,
                        ver_str,
                        peer_name,
                    );
                    continue;
                }
            };

            state.peer_requirements.push(PeerRequirement {
                consumer: parent_id,
                peer_name: peer_name.to_owned(),
                canonical,
                range,
                optional: peer.optional,
            });
            state.work_stats.peer_requirement_count =
                state.work_stats.peer_requirement_count.saturating_add(1);
        }
    }
    Ok(())
}
