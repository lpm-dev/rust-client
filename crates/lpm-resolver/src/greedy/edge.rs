use super::deps::enqueue_child_deps;
use super::policy::{PolicyBlock, handle_no_version, handle_policy_blocked};
use super::prelude::*;
use super::state::{ResolveState, ResolvedNodeBuilder};
use super::types::{Edge, NodeId};
use super::version::{VersionPick, find_best_version_with_policy};

/// Select or reuse an exact package identity, applying overrides before a
/// missing natural candidate can fail or omit the edge.
#[cfg(test)]
pub(super) fn process_edge(
    edge: &Edge,
    info: &CachedPackageInfo,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    process_edge_with_preferred(edge, info, None, state)
}

pub(super) fn process_edge_with_preferred(
    edge: &Edge,
    info: &CachedPackageInfo,
    preferred: Option<NpmVersion>,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    state.work_stats.edge_process_count = state.work_stats.edge_process_count.saturating_add(1);
    if state.overrides.is_empty() {
        return process_edge_inner(
            edge,
            info,
            preferred.map(|version| (version, false, None)),
            state,
        );
    }

    let parent =
        (edge.parent != 0).then(|| state.nodes[edge.parent as usize].canonical.to_string());
    let canonical = edge.canonical.to_string();
    let natural_pick = preferred.map_or_else(
        || find_best_version_with_policy(&edge.canonical, info, &edge.range, &state.policy),
        VersionPick::Picked,
    );
    let natural = match &natural_pick {
        VersionPick::Picked(version) => Some(version),
        _ => None,
    };
    if let Some(entry) = state
        .overrides
        .find_match_optional(&canonical, natural, parent.as_deref())
    {
        match select_override_target(&edge.canonical, info, &entry.target, &state.policy) {
            Ok(forced) => {
                let hit = OverrideHit::changed_selection(
                    entry,
                    canonical,
                    natural,
                    &forced,
                    parent.as_deref(),
                );
                return process_edge_inner(edge, info, Some((forced, true, hit)), state);
            }
            Err(rejection) => tracing::warn!(
                "override {} could not select target {} for {}: {}",
                entry.raw_key,
                entry.target.raw(),
                canonical,
                rejection,
            ),
        }
    }
    match natural_pick {
        VersionPick::Picked(version) => {
            process_edge_inner(edge, info, Some((version, false, None)), state)
        }
        VersionPick::NoSatisfying => handle_no_version(edge, info, false, state),
        VersionPick::BlockedByReleaseAge {
            version,
            remaining_secs,
            minimum_secs,
        } => handle_policy_blocked(
            edge,
            PolicyBlock::ReleaseAge {
                version,
                remaining_secs,
                minimum_secs,
            },
            state,
        ),
        VersionPick::BlockedByTrustPolicy { version, reason } => {
            handle_policy_blocked(edge, PolicyBlock::TrustPolicy { version, reason }, state)
        }
    }
}

fn edge_is_optional_in_context(edge: &Edge, state: &ResolveState) -> bool {
    edge.behavior.optional || state.nodes[edge.parent as usize].optional
}

pub(super) fn mark_node_required_closure(state: &mut ResolveState, node_id: NodeId) {
    let mut pending = Vec::with_capacity(64);
    pending.push(node_id);
    while let Some(node_id) = pending.pop() {
        let node = &mut state.nodes[node_id as usize];
        if !node.optional {
            continue;
        }
        node.optional = false;
        pending.extend(node.children.iter().map(|(_, child_id)| *child_id));
    }
}

fn newest_satisfying_root_node(
    state: &ResolveState,
    edge: &Edge,
    info: &CachedPackageInfo,
) -> Option<NodeId> {
    state
        .nodes
        .first()?
        .children
        .iter()
        .filter(|(local_name, _)| state.root_deps.contains_key(local_name))
        .filter_map(|(_, id)| {
            let node = state.nodes.get(*id as usize)?;
            (node.canonical == edge.canonical && info.range_satisfies(&edge.range, &node.version))
                .then_some((&node.version, *id))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, id)| id)
}

/// Compatible transitive edges prefer a manifest-root version unless an
/// override requires exact identity.
fn process_edge_inner(
    edge: &Edge,
    info: &CachedPackageInfo,
    selected: Option<(NpmVersion, bool, Option<OverrideHit>)>,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    let is_root_edge = edge.parent == 0;

    let (target_version, override_selected, override_hit) = match selected {
        Some(selection) => selection,
        None => {
            let version = match find_best_version_with_policy(
                &edge.canonical,
                info,
                &edge.range,
                &state.policy,
            ) {
                VersionPick::Picked(v) => v,
                VersionPick::NoSatisfying => {
                    return handle_no_version(edge, info, false, state);
                }
                VersionPick::BlockedByReleaseAge {
                    version,
                    remaining_secs,
                    minimum_secs,
                } => {
                    return handle_policy_blocked(
                        edge,
                        PolicyBlock::ReleaseAge {
                            version,
                            remaining_secs,
                            minimum_secs,
                        },
                        state,
                    );
                }
                VersionPick::BlockedByTrustPolicy { version, reason } => {
                    return handle_policy_blocked(
                        edge,
                        PolicyBlock::TrustPolicy { version, reason },
                        state,
                    );
                }
            };
            (version, false, None)
        }
    };

    match release_age_status_for_version(&edge.canonical, info, &target_version, &state.policy) {
        ReleaseTimeStatus::Allowed => {}
        ReleaseTimeStatus::Missing => {
            return handle_policy_blocked(
                edge,
                PolicyBlock::ReleaseAge {
                    version: target_version,
                    remaining_secs: state.policy.minimum_release_age_secs(),
                    minimum_secs: state.policy.minimum_release_age_secs(),
                },
                state,
            );
        }
        ReleaseTimeStatus::TooNew { remaining_secs } => {
            return handle_policy_blocked(
                edge,
                PolicyBlock::ReleaseAge {
                    version: target_version,
                    remaining_secs,
                    minimum_secs: state.policy.minimum_release_age_secs(),
                },
                state,
            );
        }
    }
    if state.policy.trust_policy().is_no_downgrade()
        && let Some(reason) = trust_downgrade_violation(info, &target_version)
    {
        return handle_policy_blocked(
            edge,
            PolicyBlock::TrustPolicy {
                version: target_version,
                reason,
            },
            state,
        );
    }

    let split_gate = !state.overrides.split_targets().is_empty()
        && state
            .overrides
            .split_targets()
            .contains(&edge.canonical.to_string());
    let must_exact_match = is_root_edge || override_selected || split_gate;
    let root_id = if must_exact_match {
        None
    } else {
        newest_satisfying_root_node(state, edge, info)
    };
    let existing_id = root_id.or_else(|| {
        state.resolved.get(&edge.canonical).and_then(|nodes| {
            nodes
                .iter()
                .find(|(version, _)| version == &target_version)
                .map(|(_, id)| *id)
        })
    });

    let child_id = match existing_id {
        Some(id) => {
            if !edge_is_optional_in_context(edge, state) {
                mark_node_required_closure(state, id);
            }
            state.work_stats.edge_reuse_count = state.work_stats.edge_reuse_count.saturating_add(1);
            if state.nodes[id as usize].version == target_version {
                state.work_stats.edge_reuse_exact_count =
                    state.work_stats.edge_reuse_exact_count.saturating_add(1);
            } else {
                state.work_stats.edge_reuse_range_count =
                    state.work_stats.edge_reuse_range_count.saturating_add(1);
            }
            id
        }
        None => {
            let new_id = state.nodes.len() as NodeId;
            let incoming_optional = edge_is_optional_in_context(edge, state);
            state.work_stats.node_allocated_count =
                state.work_stats.node_allocated_count.saturating_add(1);
            state.nodes.push(ResolvedNodeBuilder {
                canonical: edge.canonical.clone(),
                version: target_version.clone(),
                optional: incoming_optional,
                children: Vec::new(),
            });
            state
                .resolved
                .entry(edge.canonical.clone())
                .or_default()
                .push((target_version.clone(), new_id));

            // Enqueue this version's deps once. Different versions of
            // the same canonical each get their own children-enqueued
            // entry because dep lists are version-specific (lodash@4
            // has different deps from lodash@3).
            let key = (edge.canonical.clone(), target_version.clone());
            if !state.children_enqueued.contains(&key) {
                state.children_enqueued.insert(key);
                enqueue_child_deps(new_id, &edge.canonical, &target_version, info, state)?;
            }
            state.emit_selected_package(&edge.canonical, &target_version, info, incoming_optional);
            new_id
        }
    };

    // Record override AFTER node allocation so we never trace an
    // override that didn't actually take effect.
    if let Some(hit) = override_hit {
        state.overrides.record_hit(hit);
    }

    state.nodes[edge.parent as usize]
        .children
        .push((edge.local_name.clone(), child_id));
    if is_root_edge {
        state.resolve_pending_peer_bindings(&edge.canonical, &target_version, child_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEEP_PROMOTION_CHILD: &str = "LPM_TEST_DEEP_REQUIRED_PROMOTION_CHILD";

    #[test]
    fn required_promotion_handles_deep_optional_chain_without_stack_growth() {
        if std::env::var_os(DEEP_PROMOTION_CHILD).is_some() {
            let depth = 100_000usize;
            let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
            state.nodes.reserve(depth);
            for index in 0..depth {
                let children = (index + 1 < depth)
                    .then(|| ("child".to_string(), (index + 1) as NodeId))
                    .into_iter()
                    .collect();
                state.nodes.push(ResolvedNodeBuilder {
                    canonical: CanonicalKey::Root,
                    version: NpmVersion::new(0, 0, 0),
                    optional: true,
                    children,
                });
            }

            mark_node_required_closure(&mut state, 0);

            assert!(state.nodes.iter().all(|node| !node.optional));
            return;
        }

        let status =
            std::process::Command::new(std::env::current_exe().expect("current test binary"))
                .args([
                    "--exact",
                    "greedy::edge::tests::required_promotion_handles_deep_optional_chain_without_stack_growth",
                    "--nocapture",
                ])
                .env(DEEP_PROMOTION_CHILD, "1")
                .status()
                .expect("run deep-promotion child process");
        assert!(
            status.success(),
            "deep required promotion aborted: {status}"
        );
    }
}
