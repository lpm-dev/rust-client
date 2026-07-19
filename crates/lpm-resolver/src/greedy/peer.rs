use super::prelude::*;
use super::state::ResolveState;
use super::types::{DepBehavior, Edge, PeerConflictReport, PeerRequirement};

// ── Eager peer auto-install drain ─────────────────────────────────
//
// Design:
//   - Peer requirements are collected during `enqueue_child_deps`
//     onto `state.peer_requirements`, NEVER as `task_queue` edges.
//   - After the main task_queue drains, a peer-drain pass runs:
//     1. Group requirements by `canonical`.
//     2. For each group, check if any node in `state.resolved` for
//        that canonical satisfies EVERY consumer's range. Yes → skip
//        (the existing `into_resolved_packages` peer derivation will
//        record the consumer→peer edge from cache).
//     3. If unsatisfied AND `auto_install_peers` is on AND at least
//        one consumer is non-optional, look up the canonical's
//        manifest (arm-specific fetch closure), find the newest
//        version satisfying every consumer's range, and synthesize a
//        ROOT-SCOPED ambient `Edge` pinning that exact version.
//     4. If no version satisfies every required consumer's range →
//        `ResolveError::PeerConflict` (the user must fix the manifest
//        or pin via `lpm.overrides`).
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
    /// Some node already in `state.resolved` for this canonical
    /// satisfies every requirement in the group. No work to do —
    /// `into_resolved_packages` will record the per-consumer peer
    /// edges from the metadata cache.
    SatisfiedByExisting,
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
        if !reqs.iter().all(|requirement| {
            requirement.provider_source.is_none() && requirement.range.satisfies(v)
        }) {
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
            if reqs[i].provider_source.is_none() && reqs[i].range.satisfies(v) {
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

/// True iff at least one node currently in `state.resolved[canonical]`
/// is at a version that satisfies EVERY requirement in the group. The
/// existing `into_resolved_packages` peer-derivation pass picks up the
/// resolved version from `resolved_by_canonical`, so a satisfied group
/// needs no further work.
fn group_satisfied_by_existing(
    state: &ResolveState,
    canonical: &CanonicalKey,
    reqs: &[&PeerRequirement],
) -> bool {
    let canonical_name = canonical.to_string();
    if state.explicit_peer_providers.iter().any(|provider| {
        reqs.iter().all(|requirement| {
            provider.local_name == requirement.peer_name
                && requirement.provider_source.as_ref().map_or_else(
                    || {
                        provider.package_name == canonical_name
                            && provider
                                .parsed_version()
                                .is_some_and(|version| requirement.range.satisfies(version))
                    },
                    |required_source| required_source.matches_provider(&provider.source),
                )
        })
    }) {
        return true;
    }

    state.resolved.get(canonical).is_some_and(|nodes| {
        nodes.iter().any(|(version, _)| {
            reqs.iter().all(|requirement| {
                requirement.provider_source.is_none() && requirement.range.satisfies(version)
            })
        })
    })
}

pub(super) fn peer_resolution_cache_key(
    canonical: &CanonicalKey,
    reqs: &[&PeerRequirement],
) -> PeerResolutionCacheKey {
    let mut parent_peers: Vec<(String, String, bool)> = Vec::with_capacity(reqs.len());
    for req in reqs {
        parent_peers.push((
            req.peer_name.clone(),
            req.raw_specifier.clone(),
            req.optional,
        ));
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
        .filter(|req| {
            !req.optional && (req.provider_source.is_some() || !req.range.satisfies(chosen))
        })
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
    (consumer_canonical, req.raw_specifier.clone())
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
///   - no node in `state.resolved` for the canonical satisfies any
///     consumer's range (i.e., not already met by an ancestor);
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
        if reqs
            .iter()
            .any(|r| !r.optional && !r.install_source.is_registry())
        {
            continue;
        }
        // Already satisfied by an existing node in the resolved tree.
        if group_satisfied_by_existing(state, canonical, &reqs) {
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

    // Group by local peer slot and canonical target, deterministically. The HashMap walk would
    // produce non-reproducible synthesis order; collect-then-sort
    // gives byte-identical lockfile output across runs.
    let mut grouped: HashMap<(String, CanonicalKey), Vec<PeerRequirement>> = HashMap::new();
    for req in pending {
        grouped
            .entry((req.peer_name.clone(), req.canonical.clone()))
            .or_default()
            .push(req);
    }
    let mut group_keys: Vec<(String, CanonicalKey)> = grouped.keys().cloned().collect();
    group_keys.sort_by(|left, right| {
        (left.0.as_str(), left.1.to_string()).cmp(&(right.0.as_str(), right.1.to_string()))
    });

    let mut synthesized: Vec<Edge> = Vec::new();
    for (peer_name, canonical) in group_keys {
        let reqs_owned = grouped
            .remove(&(peer_name.clone(), canonical.clone()))
            .expect("just collected key");
        let reqs: Vec<&PeerRequirement> = reqs_owned.iter().collect();

        let outcome = classify_peer_group(
            state,
            &canonical,
            &reqs,
            auto_install_peers,
            &mut fetch_manifest,
        )
        .await?;

        match outcome {
            PeerDrainOutcome::SatisfiedByExisting => continue,
            PeerDrainOutcome::SkippedOptOut => continue,
            PeerDrainOutcome::Synthesize { chosen } => {
                synthesize_ambient_edge(
                    state,
                    &peer_name,
                    &canonical,
                    &chosen,
                    reqs_owned.len(),
                    &mut synthesized,
                )?;
            }
            PeerDrainOutcome::BestEffortSynthesize {
                chosen,
                unsatisfied,
            } => {
                synthesize_ambient_edge(
                    state,
                    &peer_name,
                    &canonical,
                    &chosen,
                    reqs_owned.len(),
                    &mut synthesized,
                )?;
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
                    reqs_owned.len() - unsatisfied.len(),
                    reqs_owned.iter().filter(|r| !r.optional).count(),
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

    Ok(synthesized)
}

/// Push a single ambient root-scoped Edge for the chosen peer version
/// and record the canonical on `state.ambient_peer_installs`. Shared
/// between the strict-satisfies-all path and the best-effort
/// satisfies-most fallback so both paths produce byte-identical edges.
fn synthesize_ambient_edge(
    state: &mut ResolveState,
    peer_name: &str,
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
        local_name: peer_name.to_string(),
        canonical: canonical.clone(),
        range: exact_range,
        behavior: DepBehavior {
            required: true,
            peer: false,
            optional: false,
        },
    });
    if peer_name != canonical_name {
        state
            .root_aliases
            .insert(peer_name.to_string(), canonical_name);
    }
    state.ambient_peer_installs.push(peer_name.to_string());
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
    state: &ResolveState,
    canonical: &CanonicalKey,
    reqs: &[&PeerRequirement],
    auto_install_peers: bool,
    fetch_manifest: &mut F,
) -> Result<PeerDrainOutcome, ResolveError>
where
    F: FnMut(CanonicalKey) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<CachedPackageInfo>, ResolveError>>,
{
    // Step 1 — already satisfied?
    if group_satisfied_by_existing(state, canonical, reqs) {
        return Ok(PeerDrainOutcome::SatisfiedByExisting);
    }

    // Step 2 — opt-out gates. If every requirement is optional, the
    // manifest author asked us not to fail; same skip path as
    // `auto_install_peers = false`.
    let any_required = reqs.iter().any(|r| !r.optional);
    if !any_required || !auto_install_peers {
        return Ok(PeerDrainOutcome::SkippedOptOut);
    }

    let canonical_name = canonical.to_string();
    let has_explicit_root_registry_provider = state
        .resolved
        .get(canonical)
        .is_some_and(|versions| !versions.is_empty())
        && reqs.first().is_some_and(|requirement| {
            state.root_deps.contains_key(&requirement.peer_name)
                && state
                    .root_aliases
                    .get(&requirement.peer_name)
                    .is_none_or(|target| target == &canonical_name)
        });
    if let Some(requirement) = reqs.iter().find(|requirement| {
        !requirement.optional
            && !requirement.install_source.is_registry()
            && (requirement.provider_source.is_some() || !has_explicit_root_registry_provider)
    }) && let Some((scheme, specifier)) = requirement.install_source.unsupported_details()
    {
        let consumer = state.nodes.get(requirement.consumer as usize).map_or_else(
            || "<unknown>".to_string(),
            |node| format!("{}@{}", node.canonical, node.version),
        );
        return Err(ResolveError::UnsupportedPeerAutoInstallSource {
            consumer,
            peer: requirement.peer_name.clone(),
            specifier: specifier.to_string(),
            scheme: scheme.to_string(),
        });
    }
    if reqs
        .iter()
        .any(|requirement| !requirement.optional && !requirement.install_source.is_registry())
    {
        return Ok(PeerDrainOutcome::SkippedOptOut);
    }

    let cache_key = peer_resolution_cache_key(canonical, reqs);
    if let Some(cached) = state.peer_resolution_cache.get(&cache_key) {
        return Ok(cached.value().to_outcome(state, reqs));
    }

    // Step 3 — synthesis path. Fetch the manifest, find the version
    // satisfying every consumer's range. Raising `PeerConflict` when no
    // version threads every range breaks real-world installs whose
    // TRANSITIVE tree declares incompatible peer ranges (e.g. nestjs's
    // chain pulling both `ajv-keywords@5` peer'ing ajv@^6 and
    // `ajv-keywords@8` peer'ing ajv@^8). npm v7+ + pnpm hoist a single top-level peer
    // and warn about the stuck consumers; lpm now matches.
    let info = fetch_manifest(canonical.clone()).await?;
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
                (consumer_canonical, r.raw_specifier.clone(), r.optional)
            })
            .collect(),
    })
}
