use super::deps::enqueue_child_deps;
use super::policy::{
    PolicyBlock, apply_override_target_greedy, handle_no_version, handle_policy_blocked,
};
use super::prelude::*;
use super::state::{ResolveState, ResolvedNodeBuilder};
use super::types::{Edge, NodeId};
use super::version::{VersionPick, find_best_version_with_policy};

/// Process one edge: reuse an existing node whose version satisfies
/// the edge's range, OR allocate a new node for the best version
/// matching the range. Mirrors bun's "dedupe when compatible,
/// allocate when not" model — same as npm + pnpm semantics. PubGrub's
/// flat-then-split-retry workaround is unnecessary because
/// multi-version is the natural representation here.
///
/// **Overrides.** When `state.overrides` is non-empty, we compute the
/// natural pick FIRST and consult `find_match` for an applicable
/// [`OverrideTarget`]. A successful override produces a forced version that
/// becomes the dedupe target — reuse falls through to exact-version-match
/// (so two parents forcing different versions allocate independent nodes),
/// and the [`OverrideHit`] is recorded for the install summary. The
/// empty-overrides hot path skips this entire branch with one
/// [`OverrideSet::is_empty`] check (single-bool indirection, zero allocs).
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
    // Hot path: zero-overrides installs (the common case) skip the
    // natural-pick computation entirely. Behavior matches the pre-
    // override implementation byte-for-byte.
    if state.overrides.is_empty() {
        return process_edge_inner(edge, info, preferred.map(|version| (version, None)), state);
    }

    // Slow path: at least one override entry exists. Compute the
    // natural pick (the version greedy WOULD pick without any
    // override) and consult `find_match`.
    let parent_ctx_owned = if edge.parent == 0 {
        None
    } else {
        Some(state.nodes[edge.parent as usize].canonical.to_string())
    };
    let canonical_name = edge.canonical.to_string();

    let natural_pick = preferred.map_or_else(
        || find_best_version_with_policy(&edge.canonical, info, &edge.range, &state.policy),
        VersionPick::Picked,
    );
    let natural_ver = match &natural_pick {
        VersionPick::Picked(v) => Some(v.clone()),
        VersionPick::NoSatisfying
        | VersionPick::BlockedByReleaseAge { .. }
        | VersionPick::BlockedByTrustPolicy { .. } => None,
    };

    // No natural version means there's nothing to evaluate the
    // override selector's range filter against. Mirrors the pubgrub
    // arm — when natural is None, override can't apply, so we surface
    // the no-version outcome directly.
    let Some(natural) = natural_ver else {
        return match natural_pick {
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
            VersionPick::Picked(_) => unreachable!(),
        };
    };

    let parent_ctx_ref = parent_ctx_owned.as_deref();
    let override_outcome: Option<(NpmVersion, OverrideHit)> = match state.overrides.find_match(
        &canonical_name,
        &natural,
        parent_ctx_ref,
    ) {
        Some(entry) => {
            match apply_override_target_greedy(
                &edge.canonical,
                info,
                &entry.target,
                &edge.range,
                &state.policy,
            ) {
                Some(forced) => {
                    let hit = OverrideHit {
                        raw_key: entry.raw_key.clone(),
                        source: entry.source,
                        package: canonical_name.clone(),
                        from_version: natural.to_string(),
                        to_version: forced.to_string(),
                        via_parent: parent_ctx_ref.map(str::to_string),
                    };
                    tracing::debug!(
                        "override applied: {} {} → {} (via {})",
                        hit.package,
                        hit.from_version,
                        hit.to_version,
                        hit.source_display()
                    );
                    Some((forced, hit))
                }
                None => {
                    // Mirrors pubgrub arm's "irreconcilable override" warn:
                    // target is outside the consumer range. We fall through
                    // to the natural version — DO NOT silently pretend the
                    // override applied. Fall through to the natural version.
                    tracing::warn!(
                        "override {} could not be satisfied: target {} is outside consumer range for {}",
                        entry.raw_key,
                        entry.target.raw(),
                        canonical_name
                    );
                    None
                }
            }
        }
        None => None,
    };

    process_edge_inner(edge, info, Some((natural, override_outcome)), state)
}

fn edge_is_optional_in_context(edge: &Edge, state: &ResolveState) -> bool {
    edge.behavior.optional || state.nodes[edge.parent as usize].optional
}

fn mark_node_required_closure(state: &mut ResolveState, node_id: NodeId) {
    let idx = node_id as usize;
    if !state.nodes[idx].optional {
        return;
    }
    state.nodes[idx].optional = false;
    let children: Vec<NodeId> = state.nodes[idx]
        .children
        .iter()
        .map(|(_, child_id)| *child_id)
        .collect();
    for child_id in children {
        mark_node_required_closure(state, child_id);
    }
}

fn newest_existing_satisfying_node(
    nodes: &[(NpmVersion, NodeId)],
    range: &NpmRange,
) -> Option<NodeId> {
    nodes
        .iter()
        .filter(|(version, _)| range.satisfies(version))
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, id)| *id)
}

/// Core reuse-or-allocate logic. The `forced` parameter, when present,
/// carries (natural_version, optional_override) computed by the override
/// branch in [`process_edge`]. When `None`, non-root edges use the
/// pre-override fast path: any existing node satisfying the edge range
/// is reused, otherwise [`find_best_version`] picks the newest match.
/// Root edges pick their natural target first so an explicit top-level
/// dependency cannot be down-selected by an earlier transitive edge that
/// only happens to satisfy a broad range.
fn process_edge_inner(
    edge: &Edge,
    info: &CachedPackageInfo,
    forced: Option<(NpmVersion, Option<(NpmVersion, OverrideHit)>)>,
    state: &mut ResolveState,
) -> Result<(), ResolveError> {
    let is_root_edge = edge.parent == 0;

    // Determine the target version for THIS edge. Non-root edges on
    // the no-overrides path can reuse whichever existing node satisfies
    // the range. Root edges, override hits, and override-aware misses use
    // the natural or forced target first, then dedupe against that target.
    let (target_version, override_hit): (NpmVersion, Option<OverrideHit>) = match forced {
        Some((natural, Some((forced_v, hit)))) => {
            let _ = natural;
            (forced_v, Some(hit))
        }
        Some((natural, None)) => (natural, None),
        None => {
            // Hot path — no overrides parsed. Reuse-on-range-satisfies
            // applies only below the root; root deps define the visible
            // install contract and must choose their own target version.
            if !is_root_edge {
                let existing_id: Option<NodeId> = state
                    .resolved
                    .get(&edge.canonical)
                    .and_then(|nodes| newest_existing_satisfying_node(nodes, &edge.range));
                if let Some(id) = existing_id {
                    if !edge_is_optional_in_context(edge, state) {
                        mark_node_required_closure(state, id);
                    }
                    state.work_stats.edge_reuse_count =
                        state.work_stats.edge_reuse_count.saturating_add(1);
                    state.work_stats.edge_reuse_range_count =
                        state.work_stats.edge_reuse_range_count.saturating_add(1);
                    state.nodes[edge.parent as usize]
                        .children
                        .push((edge.local_name.clone(), id));
                    return Ok(());
                }
            }
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
            (version, None)
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

    // Reuse-or-allocate against `target_version`.
    //
    // **Dedupe rule.** Exact-match when EITHER (a) this edge applied an
    // override, OR (b) the canonical is in `OverrideSet::split_targets()`
    // — i.e., at least one path-selector targets it. Otherwise
    // range-satisfies (the pre-override hot-path semantic).
    //
    // Why split-targeted canonicals must use exact-match even when THIS
    // edge didn't apply an override: a sibling edge from a path-matching
    // parent may have already allocated a forced node at a different
    // version. With range-satisfies dedupe, this edge would silently
    // inherit that forced version — leaking the override into a parent
    // it wasn't selecting. Exact-match against the natural pick avoids
    // the leak; a second non-matching sibling agreeing on the same
    // natural pick still dedupes correctly.
    //
    // The hot path (no overrides parsed) is in the `forced.is_none()`
    // branch above and never reaches here, so this gate has zero cost
    // on installs without overrides. The `split_targets().is_empty()`
    // short-circuit also keeps slow-path installs with name-only
    // overrides off the `to_string()` allocation.
    let split_gate = !state.overrides.split_targets().is_empty()
        && state
            .overrides
            .split_targets()
            .contains(&edge.canonical.to_string());
    let must_exact_match = is_root_edge || override_hit.is_some() || split_gate;
    let existing_id: Option<NodeId> = state.resolved.get(&edge.canonical).and_then(|nodes| {
        if must_exact_match {
            nodes
                .iter()
                .find(|(v, _)| v == &target_version)
                .map(|(_, id)| *id)
        } else {
            newest_existing_satisfying_node(nodes, &edge.range)
        }
    });

    let child_id = match existing_id {
        Some(id) => {
            if !edge_is_optional_in_context(edge, state) {
                mark_node_required_closure(state, id);
            }
            state.work_stats.edge_reuse_count = state.work_stats.edge_reuse_count.saturating_add(1);
            if must_exact_match {
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
                enqueue_child_deps(new_id, &edge.canonical, &target_version, info, state);
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

    Ok(())
}
