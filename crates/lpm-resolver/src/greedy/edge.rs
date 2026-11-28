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
    if !state.nodes[node_id as usize].optional {
        return;
    }
    let mut pending = Vec::with_capacity(64);
    pending.push(node_id);
    while let Some(current_id) = pending.pop() {
        let node = &mut state.nodes[current_id as usize];
        if !node.optional {
            continue;
        }
        node.optional = false;
        let optional_edges = &state.optional_edges;
        pending.extend(
            node.children
                .iter()
                .filter(|(_, child_id)| !optional_edges.contains(&(current_id, *child_id)))
                .map(|(_, child_id)| *child_id),
        );
    }
}

pub(super) fn promote_host_materializable_closure(state: &mut ResolveState, node_id: NodeId) {
    let start = &mut state.nodes[node_id as usize];
    if start.host_materializable || !start.self_platform_compatible {
        return;
    }
    start.host_materializable = true;
    let mut pending = Vec::with_capacity(32);
    pending.push(node_id);
    while let Some(current_id) = pending.pop() {
        let deferred = {
            let node = &mut state.nodes[current_id as usize];
            node.deferred_selected_event.take().map(|mut event| {
                event.optional = node.optional;
                *event
            })
        };
        if let Some(event) = deferred {
            state.send_selected_event(event);
        }
        let child_len = state.nodes[current_id as usize].children.len();
        for idx in 0..child_len {
            let child_id = state.nodes[current_id as usize].children[idx].1;
            let child = &mut state.nodes[child_id as usize];
            if !child.host_materializable && child.self_platform_compatible {
                child.host_materializable = true;
                pending.push(child_id);
            }
        }
    }
}

fn newest_satisfying_root_node(
    state: &ResolveState,
    edge: &Edge,
    info: &CachedPackageInfo,
) -> Option<NodeId> {
    let ids = state.declared_root_nodes.get(&edge.canonical)?;
    ids.iter()
        .filter_map(|&id| {
            let node = state.nodes.get(id as usize)?;
            info.range_satisfies(&edge.range, &node.version)
                .then_some((&node.version, id))
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

    let preselected = selected.is_some();
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

    if preselected {
        match release_age_status_for_version(&edge.canonical, info, &target_version, &state.policy)
        {
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

    let parent_materializable = state.nodes[edge.parent as usize].host_materializable
        && !(is_root_edge
            && state
                .non_materializable_ambient_roots
                .contains(&edge.local_name));
    let child_id = match existing_id {
        Some(id) => {
            if !edge_is_optional_in_context(edge, state) {
                mark_node_required_closure(state, id);
            }
            if parent_materializable {
                promote_host_materializable_closure(state, id);
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
            let self_platform_compatible = !info.has_platform_metadata()
                || info.platform_is_compatible(&target_version.to_string()) != Some(false);
            let host_materializable = parent_materializable && self_platform_compatible;
            let deferred_selected_event = (!host_materializable
                && self_platform_compatible
                && state.has_selected_package_tx())
            .then(|| {
                Box::new(ResolveState::build_selected_package_event(
                    &edge.canonical,
                    &target_version,
                    info,
                    incoming_optional,
                ))
            });
            state.work_stats.node_allocated_count =
                state.work_stats.node_allocated_count.saturating_add(1);
            state.nodes.push(ResolvedNodeBuilder {
                canonical: edge.canonical.clone(),
                version: target_version.clone(),
                optional: incoming_optional,
                self_platform_compatible,
                host_materializable,
                deferred_selected_event,
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
            if host_materializable {
                state.emit_selected_package(
                    &edge.canonical,
                    &target_version,
                    info,
                    incoming_optional,
                );
            }
            new_id
        }
    };

    // Record override AFTER node allocation so we never trace an
    // override that didn't actually take effect.
    if let Some(hit) = override_hit {
        state.overrides.record_hit(hit);
    }

    let had_existing_edge = state.nodes[edge.parent as usize]
        .children
        .iter()
        .any(|(_, existing)| *existing == child_id);
    if !edge.behavior.optional {
        state.optional_edges.remove(&(edge.parent, child_id));
    } else if !had_existing_edge {
        state.optional_edges.insert((edge.parent, child_id));
    }
    state.nodes[edge.parent as usize]
        .children
        .push((edge.local_name.clone(), child_id));
    if is_root_edge {
        if state.root_deps.contains_key(&edge.local_name) {
            state
                .declared_root_nodes
                .entry(edge.canonical.clone())
                .or_default()
                .push(child_id);
        }
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
                    self_platform_compatible: true,
                    host_materializable: true,
                    deferred_selected_event: None,
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

    #[test]
    fn required_promotion_does_not_cross_optional_edges() {
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        // Node 0: shared, Node 1: optional child of shared, Node 2: regular child of shared
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::from_dep_name("shared"),
            version: NpmVersion::new(1, 0, 0),
            optional: true,
            self_platform_compatible: true,
            host_materializable: false,
            deferred_selected_event: None,
            children: vec![("opt-child".into(), 1), ("reg-child".into(), 2)],
        });
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::from_dep_name("opt-child"),
            version: NpmVersion::new(1, 0, 0),
            optional: true,
            self_platform_compatible: true,
            host_materializable: false,
            deferred_selected_event: None,
            children: Vec::new(),
        });
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::from_dep_name("reg-child"),
            version: NpmVersion::new(1, 0, 0),
            optional: true,
            self_platform_compatible: true,
            host_materializable: false,
            deferred_selected_event: None,
            children: Vec::new(),
        });
        state.optional_edges.insert((0, 1));

        mark_node_required_closure(&mut state, 0);

        assert!(!state.nodes[0].optional, "shared becomes required");
        assert!(
            !state.nodes[2].optional,
            "regular child of shared becomes required"
        );
        assert!(
            state.nodes[1].optional,
            "optional child of shared must remain optional"
        );
    }

    #[test]
    fn selected_events_preserve_emission_order_when_channel_has_backlog() {
        let mut state = ResolveState::new(HashMap::new(), OverrideSet::empty());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        state.set_selected_package_tx(Some(tx));
        let make_event = |name: &str| crate::SelectedPackageEvent {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            is_lpm: false,
            tarball_url: None,
            integrity: None,
            unpacked_size: None,
            platform: None,
            node_engine: None,
            optional: false,
        };

        state.send_selected_event(make_event("first"));
        state.send_selected_event(make_event("second"));
        // Drain "first" so the channel has space while "second" is still queued.
        assert_eq!(rx.try_recv().unwrap().name, "first");
        state.send_selected_event(make_event("third"));

        // "third" must queue behind "second", not overtake it.
        assert!(
            rx.try_recv().is_err(),
            "third must not overtake backlogged second"
        );
        assert_eq!(state.pending_selected_packages.len(), 2);
        assert_eq!(state.pending_selected_packages[0].name, "second");
        assert_eq!(state.pending_selected_packages[1].name, "third");
    }
}
