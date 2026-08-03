use super::policy::apply_peer_override_target_greedy;
use super::prelude::*;
use super::state::ResolveState;
use super::types::{DepBehavior, Edge, PeerConflictReport, PeerRequirement};
use super::version::{VersionPick, find_best_version_with_policy};

// ── Eager peer auto-install drain ─────────────────────────────────
//
// Design:
//   - Peer requirements are collected during `enqueue_child_deps`
//     onto `state.peer_requirements`, NEVER as `task_queue` edges.
//   - After the main task_queue drains, a peer-drain pass runs:
//     1. Group requirements by `canonical`.
//     2. Bind each consumer to the newest matching version already
//        present in `state.resolved`.
//     3. If requirements remain AND `auto_install_peers` is on AND at least
//        one consumer is non-optional, look up the canonical's
//        manifest (arm-specific fetch closure), find the newest
//        version satisfying every consumer's range, and synthesize a
//        ROOT-SCOPED ambient `Edge` pinning that exact version.
//     4. If no version satisfies every remaining required range, pick
//        the version satisfying the most consumers and report the rest.
//        Hard-fail only when no published version satisfies any required
//        consumer.
//   - Caller pushes synthesized edges to `task_queue`, re-drains the
//     main loop, and re-runs the drain pass. Repeat until both
//     queues are empty (transitive peers from ambient installs may
//     spawn further requirements).
//
// **Architectural correction (vs. earlier draft).** Peers are
// deliberately NOT routed as `n.children` edges of the consumer.
// `ResolvedPackage.dependencies` and `ResolvedPackage.peers` are
// distinct fields; the v2 store's graph-key derivation depends on
// the separation
// (`ResolvedPackage.dependencies` / `ResolvedPackage.peers`).
// Smuggling peers in as children would break peer-divergent link-
// entry isolation under v2 (default). Hence: ambient install at
// ROOT scope, satisfying the peer's canonical from the side without
// modifying the consumer's child list.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PeerResolutionCacheKey {
    canonical: CanonicalKey,
    sorted_parent_peers_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub(super) enum CachedPeerResolution {
    Synthesize { chosen: NpmVersion },
    BestEffortSynthesize { chosen: NpmVersion },
}

impl CachedPeerResolution {
    fn to_outcome(&self, state: &ResolveState, reqs: &[&PeerRequirement]) -> PeerDrainOutcome {
        match self {
            Self::Synthesize { chosen } => PeerDrainOutcome::Synthesize {
                chosen: chosen.clone(),
            },
            Self::BestEffortSynthesize { chosen } => PeerDrainOutcome::BestEffortSynthesize {
                chosen: chosen.clone(),
                unsatisfied: unsatisfied_required_consumers(state, reqs, chosen),
            },
        }
    }
}

/// Classification outcome for a single peer-canonical group during
/// the drain pass.
enum PeerDrainOutcome {
    /// All consumers in the group declared the peer as optional, OR
    /// `auto_install_peers` is off. Skip without synthesis;
    /// `check_unmet_peers` handles user-visible output.
    SkippedOptOut,
    /// At least one consumer is required and the group can be
    /// satisfied by version `chosen` from the canonical's manifest.
    /// Caller synthesizes a root-scoped ambient `Edge` with an
    /// exact-version range pinning `chosen`. `find_version_satisfying_all`
    /// applies the platform filter, so a returned version is always
    /// platform-compatible — the synthesis path never bumps
    /// `state.platform_skipped`.
    Synthesize { chosen: NpmVersion },
    /// Best-effort synthesis: required consumer ranges are
    /// pairwise-incompatible, so no single version satisfies every
    /// consumer. Caller still synthesizes a root-scoped ambient Edge
    /// at `chosen` (the version satisfying the most consumers, ties
    /// broken by newest), AND records a [`PeerConflictReport`] so the
    /// install pipeline can warn about the unsatisfied consumers.
    /// Mirrors npm v7+ / pnpm behavior — pick one peer at top level,
    /// warn the rest. The unreachable terminal case (no version
    /// satisfies ANY required consumer) keeps the hard
    /// [`ResolveError::PeerConflict`] surface.
    BestEffortSynthesize {
        chosen: NpmVersion,
        unsatisfied: Vec<(String, String)>, // (consumer_canonical, range)
    },
}

/// Walk `info.versions` newest-first, return the first version that
/// satisfies EVERY requirement's range AND is platform-compatible.
/// Mirrors `find_best_version`'s contract for a single range, but
/// generalized to N ranges that all must be satisfied simultaneously.
///
/// Returns `None` when no version threads every range; callers turn
/// that into a best-effort fallback via [`find_version_satisfying_most`]
/// (warn + synthesize the most-satisfying version) or a silent skip
/// (all consumers optional).
fn find_version_satisfying_all(
    info: &CachedPackageInfo,
    reqs: &[&PeerRequirement],
) -> Option<NpmVersion> {
    for v in &info.versions {
        // Every requirement's range must accept this version.
        if !reqs.iter().all(|r| r.range.satisfies(v)) {
            continue;
        }
        // Platform filter — same gate the regular dep path uses, so
        // an ambient install never lands a tarball the current OS/CPU
        // can't use.
        let platform_ok = info.platform.is_empty()
            || info
                .platform
                .get(&v.to_string())
                .is_none_or(crate::provider::is_platform_compatible);
        if !platform_ok {
            continue;
        }
        return Some(v.clone());
    }
    None
}

/// Best-effort fallback when no version satisfies EVERY required
/// consumer's range (transitive peer conflict). Returns
/// `Some((chosen, unsatisfied_required_indices))` where:
/// - `chosen` is the platform-compatible version that satisfies the
///   most REQUIRED consumer ranges (ties broken by newest semver — the
///   `info.versions` walk is already newest-first);
/// - `unsatisfied_required_indices` indexes into `reqs` for required
///   consumers whose range does NOT include `chosen`. Optional
///   consumers are excluded from the unsatisfied list — they're never
///   surfaced as warnings.
///
/// Returns `None` when no platform-compatible version satisfies even
/// ONE required consumer's range — that's the truly-irreconcilable
/// terminal case the caller should turn into a hard `PeerConflict`
/// error.
///
/// Mirrors npm v7+ / pnpm hoisted-mode behavior: pick a single
/// top-level peer version, warn about consumers stuck with the wrong
/// one. lpm pre-fix raised `PeerConflict` here, blocking real-world
/// installs (e.g. nestjs/typescript-starter's transitive
/// ajv-keywords@5 vs @8 chain).
fn find_version_satisfying_most<'a>(
    info: &CachedPackageInfo,
    reqs: &'a [&'a PeerRequirement],
) -> Option<(NpmVersion, Vec<usize>)> {
    let required_indices: Vec<usize> = reqs
        .iter()
        .enumerate()
        .filter_map(|(i, r)| (!r.optional).then_some(i))
        .collect();
    if required_indices.is_empty() {
        return None;
    }

    let mut best: Option<(NpmVersion, usize, Vec<usize>)> = None;
    for v in &info.versions {
        let platform_ok = info.platform.is_empty()
            || info
                .platform
                .get(&v.to_string())
                .is_none_or(crate::provider::is_platform_compatible);
        if !platform_ok {
            continue;
        }
        let mut hits = 0usize;
        let mut misses: Vec<usize> = Vec::new();
        for &i in &required_indices {
            if reqs[i].range.satisfies(v) {
                hits += 1;
            } else {
                misses.push(i);
            }
        }
        if hits == 0 {
            continue;
        }
        // Newest-first walk + strictly-greater hit count = stable
        // tiebreak on newest. Equal hit count loses to the version
        // already chosen (which was newer in the walk).
        match &best {
            None => best = Some((v.clone(), hits, misses)),
            Some((_, prev_hits, _)) if hits > *prev_hits => best = Some((v.clone(), hits, misses)),
            _ => {}
        }
    }
    best.map(|(v, _, misses)| (v, misses))
}

fn newest_existing_version_for_requirement(
    state: &ResolveState,
    canonical: &CanonicalKey,
    requirement: &PeerRequirement,
) -> Option<NpmVersion> {
    let nodes = state.resolved.get(canonical)?;
    nodes
        .iter()
        .filter(|(version, _)| requirement.range.satisfies(version))
        .map(|(version, _)| version)
        .max()
        .cloned()
}

async fn apply_peer_overrides<F, Fut>(
    state: &mut ResolveState,
    canonical: &CanonicalKey,
    requirements: &mut [PeerRequirement],
    fetch_manifest: &mut F,
) -> Result<(), ResolveError>
where
    F: FnMut(CanonicalKey) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>>,
{
    if state.overrides.is_empty() {
        return Ok(());
    }

    let canonical_name = canonical.to_string();
    if !state.overrides.may_match_package(&canonical_name) {
        return Ok(());
    }

    let info = fetch_peer_manifest(state, canonical.clone(), fetch_manifest).await?;
    for requirement in requirements {
        let VersionPick::Picked(natural) =
            find_best_version_with_policy(canonical, &info, &requirement.range, &state.policy)
        else {
            continue;
        };
        let parent = state
            .nodes
            .get(requirement.consumer as usize)
            .map(|node| node.canonical.to_string());
        let Some(entry) = state
            .overrides
            .find_match(&canonical_name, &natural, parent.as_deref())
            .cloned()
        else {
            continue;
        };
        let Some(forced) =
            apply_peer_override_target_greedy(canonical, &info, &entry.target, &state.policy)
        else {
            tracing::warn!(
                "override {} could not select an eligible peer version for {}",
                entry.raw_key,
                canonical_name
            );
            continue;
        };
        requirement.range = NpmRange::parse(&forced.to_string()).map_err(|error| {
            ResolveError::Internal(format!(
                "override produced invalid peer version range '{forced}' for {canonical_name}: {error}"
            ))
        })?;
        state.overrides.record_hit(OverrideHit {
            raw_key: entry.raw_key,
            source: entry.source,
            package: canonical_name.clone(),
            from_version: natural.to_string(),
            to_version: forced.to_string(),
            via_parent: parent,
        });
    }
    Ok(())
}

fn record_peer_bindings(
    state: &mut ResolveState,
    requirements: &[&PeerRequirement],
    chosen: &NpmVersion,
) {
    for requirement in requirements {
        state
            .peer_bindings
            .entry(requirement.consumer)
            .or_default()
            .insert(requirement.peer_name.clone(), chosen.clone());
    }
}

pub(super) fn peer_resolution_cache_key(
    canonical: &CanonicalKey,
    reqs: &[&PeerRequirement],
) -> PeerResolutionCacheKey {
    let mut parent_peers: Vec<(String, String, bool)> = Vec::with_capacity(reqs.len());
    for req in reqs {
        parent_peers.push((req.peer_name.clone(), req.range.to_string(), req.optional));
    }
    parent_peers.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"lpm-peer-resolution-cache-v1\0");
    for (peer_name, range, optional) in parent_peers {
        hasher.update(peer_name.as_bytes());
        hasher.update(b"\0");
        hasher.update(range.as_bytes());
        hasher.update(b"\0");
        hasher.update(if optional {
            b"optional\0"
        } else {
            b"required\0"
        });
    }
    let digest = hasher.finalize();
    let mut sorted_parent_peers_hash = [0u8; 32];
    sorted_parent_peers_hash.copy_from_slice(&digest);

    PeerResolutionCacheKey {
        canonical: canonical.clone(),
        sorted_parent_peers_hash,
    }
}

fn unsatisfied_required_consumers(
    state: &ResolveState,
    reqs: &[&PeerRequirement],
    chosen: &NpmVersion,
) -> Vec<(String, String)> {
    reqs.iter()
        .filter(|req| !req.optional && !req.range.satisfies(chosen))
        .map(|req| peer_conflict_consumer_entry(state, req))
        .collect()
}

fn unsatisfied_required_consumers_at_indices(
    state: &ResolveState,
    reqs: &[&PeerRequirement],
    indices: Vec<usize>,
) -> Vec<(String, String)> {
    indices
        .into_iter()
        .map(|i| peer_conflict_consumer_entry(state, reqs[i]))
        .collect()
}

fn peer_conflict_consumer_entry(state: &ResolveState, req: &PeerRequirement) -> (String, String) {
    let consumer_canonical = state
        .nodes
        .get(req.consumer as usize)
        .map_or_else(|| "<unknown>".to_string(), |n| n.canonical.to_string());
    (consumer_canonical, req.range.to_string())
}

/// One peer-drain pass.
///
/// Drains the current `state.peer_requirements` snapshot (replacing
/// the field with an empty Vec so the next pass collects fresh
/// requirements from any ambient installs synthesized during this
/// pass). Returns the synthesized edges for the caller to push onto
/// `state.task_queue` and drain through the main loop.
///
/// Pick canonicals that should be speculatively prefetched concurrent with
/// the regular dep walk.
///
/// Returns canonicals from `state.peer_requirements` that satisfy
/// ALL of:
///   - at least one consumer in the group is non-optional
///     (optional-only groups never auto-install, so prefetching
///     would be wasted bandwidth);
///   - at least one required consumer has no matching version in
///     `state.resolved`;
///   - the canonical is not in `cached_canonicals` (manifest already
///     in the shared cache — the eventual drain pass will hit the
///     fast path);
///   - the canonical is not in `inflight_canonicals` (some sibling
///     dispatch already started a fetch — the dispatcher's existing
///     dedup handles us).
///
/// Returned canonicals are sorted alphabetically for deterministic
/// dispatch ordering across runs (same lockfile-equivalence guarantee
/// the regular dep loop holds).
///
/// **Pure function:** no I/O, no `&mut` parameters that would couple
/// it to the dispatcher's spawn machinery. The fused arm calls this
/// once per main-loop iteration to pick prefetch candidates, then
/// spawns metadata jobs through its existing infrastructure. Tests
/// can drive it directly with hand-built state + cached/inflight
/// sets to verify the four predicates.
pub(super) fn pick_peer_prefetch_candidates(
    state: &ResolveState,
    cached_canonicals: &dashmap::DashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    inflight_canonicals: &AHashSet<CanonicalKey>,
) -> Vec<CanonicalKey> {
    if state.peer_requirements.is_empty() {
        return Vec::new();
    }

    // Group reqs by canonical so the all-optional check is per-group,
    // not per-individual-requirement (an optional consumer alone
    // shouldn't keep a prefetch from happening when a sibling
    // required-consumer for the SAME canonical exists).
    let mut grouped: HashMap<&CanonicalKey, Vec<&PeerRequirement>> = HashMap::new();
    for req in &state.peer_requirements {
        grouped.entry(&req.canonical).or_default().push(req);
    }

    let mut picks: Vec<CanonicalKey> = Vec::new();
    for (canonical, reqs) in grouped {
        // All-optional → no auto-install regardless of cache state.
        if reqs.iter().all(|r| r.optional) {
            continue;
        }
        if reqs.iter().filter(|req| !req.optional).all(|requirement| {
            newest_existing_version_for_requirement(state, canonical, requirement).is_some()
        }) {
            continue;
        }
        // Manifest already in cache — drain pass will hit the fast
        // path; no prefetch needed.
        if cached_canonicals.contains_key(canonical) {
            continue;
        }
        // Some sibling dispatch already started a fetch for this
        // canonical (regular transitive dep is racing with us). The
        // dispatcher's `inflight` guard would dedup our spawn anyway;
        // skipping here saves the spawn allocation + the redundant
        // `dispatcher_rpc_count` bump.
        if inflight_canonicals.contains(canonical) {
            continue;
        }
        picks.push(canonical.clone());
    }

    // Deterministic dispatch order. With ~tens of peer requirements
    // even on bench/fixture-large, sort cost is negligible.
    picks.sort_by_key(|c| c.to_string());
    picks
}

/// `fetch_manifest` is the arm-specific closure that resolves a
/// canonical to its `Arc<CachedPackageInfo>`, using whatever caching
/// and dispatch machinery the calling arm has (walker arm:
/// synchronous `ensure_manifest`; fused arm: `shared_cache` lookup
/// then direct fetch on miss).
pub(super) async fn drain_peer_requirements_one_pass<F, Fut>(
    state: &mut ResolveState,
    auto_install_peers: bool,
    mut fetch_manifest: F,
) -> Result<Vec<Edge>, ResolveError>
where
    F: FnMut(CanonicalKey) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>>,
{
    // Take ownership of the current snapshot so subsequent passes
    // start clean. Synthesized ambient installs may produce further
    // peer requirements via `enqueue_child_deps`; those are caught by
    // the next pass.
    let pending = std::mem::take(&mut state.peer_requirements);
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let pass_measurement = state.peer_work_stats.begin_pass(&pending);

    // Group by canonical, deterministically. The HashMap walk would
    // produce non-reproducible synthesis order; collect-then-sort
    // gives byte-identical lockfile output across runs.
    let mut grouped: HashMap<CanonicalKey, Vec<PeerRequirement>> = HashMap::new();
    for req in pending {
        grouped.entry(req.canonical.clone()).or_default().push(req);
    }
    let mut canonicals: Vec<CanonicalKey> = grouped.keys().cloned().collect();
    canonicals.sort_by_key(|c| c.to_string());

    let mut synthesized: Vec<Edge> = Vec::new();
    for canonical in canonicals {
        state.peer_work_stats.record_group();
        let mut reqs_owned = grouped.remove(&canonical).expect("just collected key");
        apply_peer_overrides(state, &canonical, &mut reqs_owned, &mut fetch_manifest).await?;
        let mut reqs = Vec::with_capacity(reqs_owned.len());
        for requirement in &reqs_owned {
            if let Some(chosen) =
                newest_existing_version_for_requirement(state, &canonical, requirement)
            {
                record_peer_bindings(state, &[requirement], &chosen);
            } else {
                reqs.push(requirement);
            }
        }
        if reqs.is_empty() {
            state.peer_work_stats.record_already_satisfied_group();
            continue;
        }

        let outcome = classify_peer_group(
            state,
            &canonical,
            &reqs,
            auto_install_peers,
            &mut fetch_manifest,
        )
        .await?;

        match outcome {
            PeerDrainOutcome::SkippedOptOut => {
                state.peer_work_stats.record_skipped_opt_out_group();
                continue;
            }
            PeerDrainOutcome::Synthesize { chosen } => {
                record_peer_bindings(state, &reqs, &chosen);
                synthesize_ambient_edge(
                    state,
                    &canonical,
                    &chosen,
                    reqs_owned.len(),
                    &mut synthesized,
                )?;
                state.peer_work_stats.record_synthesized_edge();
            }
            PeerDrainOutcome::BestEffortSynthesize {
                chosen,
                unsatisfied,
            } => {
                let required_consumer_count = reqs.iter().filter(|req| !req.optional).count();
                let satisfied_consumer_count = reqs
                    .iter()
                    .filter(|req| !req.optional && req.range.satisfies(&chosen))
                    .count();
                record_peer_bindings(state, &reqs, &chosen);
                synthesize_ambient_edge(
                    state,
                    &canonical,
                    &chosen,
                    reqs_owned.len(),
                    &mut synthesized,
                )?;
                state.peer_work_stats.record_synthesized_edge();
                // Best-effort synthesis still installs the canonical
                // at top level — but at most one consumer range. Store
                // the conflict so install.rs can warn the user about
                // the consumers that DIDN'T match. tracing::warn!
                // surfaces in `--json=false` runs even when stderr is
                // capped; install.rs additionally formats the report
                // human-readably below the install summary.
                tracing::warn!(
                    "ambient peer-install best-effort: {} @ {} satisfies {} of {} required consumer(s); \
                     unsatisfied: {}",
                    canonical,
                    chosen,
                    satisfied_consumer_count,
                    required_consumer_count,
                    unsatisfied
                        .iter()
                        .map(|(c, r)| format!("{c} wants {r}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
                state.peer_conflicts.push(PeerConflictReport {
                    canonical: canonical.to_string(),
                    chosen_version: chosen.to_string(),
                    unsatisfied_consumers: unsatisfied,
                });
            }
        }
    }

    state.peer_work_stats.finish_pass(pass_measurement);
    Ok(synthesized)
}

/// Push a single ambient root-scoped Edge for the chosen peer version
/// and record the canonical on `state.ambient_peer_installs`. Shared
/// between the strict-satisfies-all path and the best-effort
/// satisfies-most fallback so both paths produce byte-identical edges.
fn synthesize_ambient_edge(
    state: &mut ResolveState,
    canonical: &CanonicalKey,
    chosen: &NpmVersion,
    consumer_count: usize,
    out: &mut Vec<Edge>,
) -> Result<(), ResolveError> {
    let exact_range = NpmRange::parse(&chosen.to_string()).map_err(|e| {
        ResolveError::Internal(format!(
            "synthesized exact-pin range '{chosen}' for {canonical} \
             failed to parse: {e}"
        ))
    })?;
    let canonical_name = canonical.to_string();
    out.push(Edge {
        parent: 0,
        local_name: canonical_name.clone(),
        canonical: canonical.clone(),
        range: exact_range,
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });
    state.ambient_peer_installs.push(canonical_name);
    tracing::debug!(
        "ambient-install: {} @ {} (consumers: {})",
        canonical,
        chosen,
        consumer_count,
    );
    Ok(())
}

/// Classify one peer-canonical group. Splits the satisfaction check
/// from the synthesis path so callers can short-circuit the manifest
/// fetch when it's not needed.
async fn classify_peer_group<F, Fut>(
    state: &mut ResolveState,
    canonical: &CanonicalKey,
    reqs: &[&PeerRequirement],
    auto_install_peers: bool,
    fetch_manifest: &mut F,
) -> Result<PeerDrainOutcome, ResolveError>
where
    F: FnMut(CanonicalKey) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>>,
{
    state.peer_work_stats.record_classified_group();
    // Opt-out gates. If every requirement is optional, the
    // manifest author asked us not to fail; same skip path as
    // `auto_install_peers = false`.
    let any_required = reqs.iter().any(|r| !r.optional);
    if !any_required || !auto_install_peers {
        return Ok(PeerDrainOutcome::SkippedOptOut);
    }

    let cache_key = peer_resolution_cache_key(canonical, reqs);
    let cached_outcome = state
        .peer_resolution_cache
        .get(&cache_key)
        .map(|cached| cached.value().to_outcome(state, reqs));
    if let Some(outcome) = cached_outcome {
        state.peer_work_stats.record_resolution_cache_hit();
        return Ok(outcome);
    }
    state.peer_work_stats.record_resolution_cache_miss();

    // Synthesis path. Fetch the manifest, find the version
    // satisfying every consumer's range. Raising `PeerConflict` when no
    // version threads every range breaks real-world installs whose
    // TRANSITIVE tree declares incompatible peer ranges (e.g. nestjs's
    // chain pulling both `ajv-keywords@5` peer'ing ajv@^6 and
    // `ajv-keywords@8` peer'ing ajv@^8). npm v7+ + pnpm hoist a single top-level peer
    // and warn about the stuck consumers; lpm now matches.
    let info = fetch_peer_manifest(state, canonical.clone(), fetch_manifest).await?;
    if let Some(chosen) = find_version_satisfying_all(&info, reqs) {
        let outcome = PeerDrainOutcome::Synthesize {
            chosen: chosen.clone(),
        };
        state
            .peer_resolution_cache
            .insert(cache_key, CachedPeerResolution::Synthesize { chosen });
        return Ok(outcome);
    }
    if let Some((chosen, unsatisfied_idx)) = find_version_satisfying_most(&info, reqs) {
        let unsatisfied = unsatisfied_required_consumers_at_indices(state, reqs, unsatisfied_idx);
        let outcome = PeerDrainOutcome::BestEffortSynthesize {
            chosen: chosen.clone(),
            unsatisfied,
        };
        state.peer_resolution_cache.insert(
            cache_key,
            CachedPeerResolution::BestEffortSynthesize { chosen },
        );
        return Ok(outcome);
    }
    // Truly irreconcilable: no platform-compatible version satisfies
    // any required consumer's range. Hard error — this means the
    // canonical's published versions don't include anything any
    // required consumer accepts, which the resolver can't paper over.
    Err(ResolveError::PeerConflict {
        canonical: canonical.to_string(),
        requirements: reqs
            .iter()
            .map(|r| {
                let consumer_canonical = state
                    .nodes
                    .get(r.consumer as usize)
                    .map_or_else(|| "<unknown>".to_string(), |n| n.canonical.to_string());
                (consumer_canonical, r.range.to_string(), r.optional)
            })
            .collect(),
    })
}

async fn fetch_peer_manifest<F, Fut>(
    state: &mut ResolveState,
    canonical: CanonicalKey,
    fetch_manifest: &mut F,
) -> Result<Arc<CachedPackageInfo>, ResolveError>
where
    F: FnMut(CanonicalKey) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>>,
{
    let started = std::time::Instant::now();
    let result = fetch_manifest(canonical).await;
    state
        .peer_work_stats
        .record_manifest_wait(started.elapsed());
    result
}
