use super::prelude::*;
use super::state::ResolveState;
use super::types::{DepBehavior, Edge, NodeId, PeerRequirement};
use super::version::is_workspace_specifier;

/// Read `info.deps[version]`, parse each child's range, push edges. Aliases
/// are looked up in `info.aliases[version]` and rewritten to the target
/// canonical at edge-creation time so the dispatch loop only ever has
/// canonical keys to look up.
pub(super) fn enqueue_child_deps(
    parent_id: NodeId,
    parent_canonical: &CanonicalKey,
    version: &NpmVersion,
    info: &CachedPackageInfo,
    state: &mut ResolveState,
) {
    let ver_str = version.to_string();
    let aliases = info.aliases.get(&ver_str);
    let optional_names = info.optional_dep_names.get(&ver_str);
    let bundled_names = info.bundled_dep_names.get(&ver_str);

    if let Some(deps) = info.deps.get(&ver_str) {
        // Sort for deterministic edge ordering — keeps test diffs stable
        // and the resolved tree reproducible across runs.
        let mut entries: Vec<(&String, &String)> = deps.iter().collect();
        entries.sort_by_key(|(name, _)| *name);

        for (local_name, range_str) in entries {
            // Bundled deps are vendored inside the parent's tarball
            // (`node_modules/<bundled>/` extracted alongside the parent's
            // own files). Skip enqueueing them as separate edges so the
            // resolver doesn't fetch a registry copy that the linker
            // might shadow over the bundled one. The extractor preserves
            // the in-tarball subtree implicitly; the resolver's job is
            // just to NOT introduce a redundant registry fetch.
            if bundled_names.is_some_and(|s| s.contains(local_name)) {
                tracing::debug!(
                    "skipping bundled dep {} of {}@{} — provided by parent's tarball",
                    local_name,
                    parent_canonical,
                    ver_str,
                );
                continue;
            }

            let canonical = match aliases.and_then(|a| a.get(local_name)) {
                Some(target) => CanonicalKey::from_dep_name(target),
                None => CanonicalKey::from_dep_name(local_name),
            };

            // Registry-published packages should
            // never declare `workspace:` deps (npm rejects at publish
            // time), but a malformed cache entry or a future regression
            // could land one here. Skip with a specific log line rather
            // than the generic "invalid range" branch so the diagnosis
            // points at the actual cause.
            if is_workspace_specifier(range_str) {
                tracing::warn!(
                    "ignoring transitive `workspace:` dep '{}' from {}@{} → {} \
                     (workspace: must be resolved upstream by lpm-workspace; \
                     a registry-published package should not declare it)",
                    range_str,
                    parent_canonical,
                    ver_str,
                    local_name,
                );
                continue;
            }

            let range = match NpmRange::parse(range_str) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        "invalid range '{}' on {}@{} → {}: {e}",
                        range_str,
                        parent_canonical,
                        ver_str,
                        local_name,
                    );
                    continue;
                }
            };

            let optional = state.nodes[parent_id as usize].optional
                || optional_names.is_some_and(|set| set.contains(local_name));
            if optional && !state.include_optional_dependencies {
                tracing::debug!(
                    "skipping optional dep {} of {}@{} by install option",
                    local_name,
                    parent_canonical,
                    ver_str,
                );
                continue;
            }

            state.task_queue.push_back(Edge {
                parent: parent_id,
                local_name: local_name.clone(),
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

    // Capture every `peerDependencies` entry on this (canonical, version)
    // as a `PeerRequirement`. Peers are NOT pushed onto `state.task_queue`
    // because they must NOT become `n.children` edges — see the
    // [`PeerRequirement`] doc + the v2 graph-key rationale on
    // `state.peer_requirements`.
    //
    // Same alias / workspace / range-parse defenses as the regular-deps
    // loop above; bundled-deps gate doesn't apply to peers (npm forbids
    // peerBundle interactions; no real package ships both).
    if let Some(peer_deps) = info.peer_deps.get(&ver_str) {
        let optional_peers = info.optional_peer_names.get(&ver_str);
        let peer_aliases = info.aliases.get(&ver_str);
        let mut peer_entries: Vec<(&String, &String)> = peer_deps.iter().collect();
        peer_entries.sort_by_key(|(name, _)| *name);

        for (peer_name, peer_range_str) in peer_entries {
            // `workspace:` peers from a registry-published package
            // shouldn't exist (npm rejects them at publish time).
            // Skip with a specific log rather than letting
            // `NpmRange::parse` emit an opaque error.
            if is_workspace_specifier(peer_range_str) {
                tracing::warn!(
                    "ignoring `workspace:` peer dep '{}' from {}@{} → {} \
                     (workspace: must be resolved upstream by lpm-workspace; \
                     a registry-published package should not declare it)",
                    peer_range_str,
                    parent_canonical,
                    ver_str,
                    peer_name,
                );
                continue;
            }

            // Alias-aware canonical lookup. Mirrors the regular-deps
            // loop: a `"peer-local": "npm:target@range"` declaration
            // (rare on peers, but legal) keys the requirement on
            // `target` so the resolver consults the correct manifest.
            let canonical = match peer_aliases.and_then(|a| a.get(peer_name)) {
                Some(target) => CanonicalKey::from_dep_name(target),
                None => CanonicalKey::from_dep_name(peer_name),
            };

            let range = match NpmRange::parse(peer_range_str) {
                Ok(r) => r,
                Err(e) => {
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

            let optional = optional_peers.is_some_and(|set| set.contains(peer_name));

            state.peer_requirements.push(PeerRequirement {
                consumer: parent_id,
                peer_name: peer_name.clone(),
                canonical,
                range,
                optional,
            });
            state.work_stats.peer_requirement_count =
                state.work_stats.peer_requirement_count.saturating_add(1);
        }
    }
}
