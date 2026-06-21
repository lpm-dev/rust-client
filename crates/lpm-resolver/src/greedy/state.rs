use super::peer::{CachedPeerResolution, PeerResolutionCacheKey};
use super::prelude::*;
use super::types::{DepBehavior, Edge, NodeId, PeerConflictReport, PeerRequirement};
use super::version::is_workspace_specifier;
use super::version::{VersionPick, find_best_version_with_policy_unprofiled};
use crate::resolve::SelectedPackageEvent;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ResolveWorkStats {
    pub(super) edge_process_count: u64,
    pub(super) edge_reuse_count: u64,
    pub(super) edge_reuse_range_count: u64,
    pub(super) edge_reuse_exact_count: u64,
    pub(super) node_allocated_count: u64,
    pub(super) child_edge_enqueued_count: u64,
    pub(super) peer_requirement_count: u64,
    pub(super) metadata_edge_miss_count: u64,
    pub(super) metadata_edge_miss_direct_count: u64,
    pub(super) metadata_edge_miss_latest_known_count: u64,
    pub(super) metadata_edge_miss_latest_known_direct_count: u64,
    pub(super) metadata_edge_miss_latest_satisfies_count: u64,
    pub(super) metadata_edge_miss_latest_satisfies_direct_count: u64,
    pub(super) metadata_edge_miss_latest_matches_pick_count: u64,
    pub(super) metadata_edge_miss_latest_matches_pick_direct_count: u64,
    pub(super) metadata_edge_miss_version_doc_policy_eligible_count: u64,
    pub(super) metadata_edge_miss_version_doc_policy_eligible_direct_count: u64,
    pub(super) metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count: u64,
    pub(super) metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count: u64,
    pub(super) metadata_edge_miss_exact_count: u64,
    pub(super) metadata_edge_miss_star_count: u64,
    pub(super) metadata_edge_miss_caret_count: u64,
    pub(super) metadata_edge_miss_tilde_count: u64,
    pub(super) metadata_edge_miss_comparator_count: u64,
    pub(super) metadata_edge_miss_complex_count: u64,
    pub(super) metadata_edge_miss_other_count: u64,
}

impl ResolveWorkStats {
    pub(super) fn record_metadata_edge_miss(
        &mut self,
        canonical: &CanonicalKey,
        range: &NpmRange,
        route_table: &RouteTable,
    ) {
        self.metadata_edge_miss_count = self.metadata_edge_miss_count.saturating_add(1);
        if matches!(
            canonical,
            CanonicalKey::Npm { name }
                if matches!(route_table.route_for_package(name), UpstreamRoute::NpmDirect)
        ) {
            self.metadata_edge_miss_direct_count =
                self.metadata_edge_miss_direct_count.saturating_add(1);
        }

        match metadata_edge_miss_range_shape(range) {
            MetadataEdgeMissRangeShape::Exact => {
                self.metadata_edge_miss_exact_count =
                    self.metadata_edge_miss_exact_count.saturating_add(1);
            }
            MetadataEdgeMissRangeShape::Star => {
                self.metadata_edge_miss_star_count =
                    self.metadata_edge_miss_star_count.saturating_add(1);
            }
            MetadataEdgeMissRangeShape::Caret => {
                self.metadata_edge_miss_caret_count =
                    self.metadata_edge_miss_caret_count.saturating_add(1);
            }
            MetadataEdgeMissRangeShape::Tilde => {
                self.metadata_edge_miss_tilde_count =
                    self.metadata_edge_miss_tilde_count.saturating_add(1);
            }
            MetadataEdgeMissRangeShape::Comparator => {
                self.metadata_edge_miss_comparator_count =
                    self.metadata_edge_miss_comparator_count.saturating_add(1);
            }
            MetadataEdgeMissRangeShape::Complex => {
                self.metadata_edge_miss_complex_count =
                    self.metadata_edge_miss_complex_count.saturating_add(1);
            }
            MetadataEdgeMissRangeShape::Other => {
                self.metadata_edge_miss_other_count =
                    self.metadata_edge_miss_other_count.saturating_add(1);
            }
        }
    }

    pub(super) fn record_metadata_edge_miss_latest(&mut self, miss: MetadataEdgeMissLatest<'_>) {
        let direct = matches!(
            miss.canonical,
            CanonicalKey::Npm { name }
                if matches!(miss.route_table.route_for_package(name), UpstreamRoute::NpmDirect)
        );
        let version_doc_policy_eligible =
            !miss.policy.release_age_applies_to_package(miss.canonical)
                && !miss.policy.requires_trust_history();
        if version_doc_policy_eligible {
            self.metadata_edge_miss_version_doc_policy_eligible_count = self
                .metadata_edge_miss_version_doc_policy_eligible_count
                .saturating_add(1);
            if direct {
                self.metadata_edge_miss_version_doc_policy_eligible_direct_count = self
                    .metadata_edge_miss_version_doc_policy_eligible_direct_count
                    .saturating_add(1);
            }
        }

        let Some(latest_version) = miss.latest_version else {
            return;
        };
        self.metadata_edge_miss_latest_known_count =
            self.metadata_edge_miss_latest_known_count.saturating_add(1);
        if direct {
            self.metadata_edge_miss_latest_known_direct_count = self
                .metadata_edge_miss_latest_known_direct_count
                .saturating_add(1);
        }
        if miss.range.satisfies(latest_version) {
            self.metadata_edge_miss_latest_satisfies_count = self
                .metadata_edge_miss_latest_satisfies_count
                .saturating_add(1);
            if direct {
                self.metadata_edge_miss_latest_satisfies_direct_count = self
                    .metadata_edge_miss_latest_satisfies_direct_count
                    .saturating_add(1);
            }
        }
        if miss.compare_policy_pick
            && matches!(
                find_best_version_with_policy_unprofiled(
                    miss.canonical,
                    miss.info,
                    miss.range,
                    miss.policy
                ),
                VersionPick::Picked(best) if &best == latest_version
            )
        {
            self.metadata_edge_miss_latest_matches_pick_count = self
                .metadata_edge_miss_latest_matches_pick_count
                .saturating_add(1);
            if direct {
                self.metadata_edge_miss_latest_matches_pick_direct_count = self
                    .metadata_edge_miss_latest_matches_pick_direct_count
                    .saturating_add(1);
            }
            if version_doc_policy_eligible {
                self.metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count =
                    self.metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count
                        .saturating_add(1);
                if direct {
                    self.metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count =
                        self.metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count
                            .saturating_add(1);
                }
            }
        }
    }
}

pub(super) struct MetadataEdgeMissLatest<'a> {
    pub(super) canonical: &'a CanonicalKey,
    pub(super) range: &'a NpmRange,
    pub(super) info: &'a CachedPackageInfo,
    pub(super) latest_version: Option<&'a NpmVersion>,
    pub(super) route_table: &'a RouteTable,
    pub(super) policy: &'a ResolverPolicy,
    pub(super) compare_policy_pick: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataEdgeMissRangeShape {
    Exact,
    Star,
    Caret,
    Tilde,
    Comparator,
    Complex,
    Other,
}

fn metadata_edge_miss_range_shape(range: &NpmRange) -> MetadataEdgeMissRangeShape {
    let raw = range.raw().trim();
    if raw == "*" {
        return MetadataEdgeMissRangeShape::Star;
    }
    if NpmVersion::parse(raw).is_ok() {
        return MetadataEdgeMissRangeShape::Exact;
    }
    if raw.contains("||") || raw.contains(" - ") {
        return MetadataEdgeMissRangeShape::Complex;
    }
    if raw.contains(' ') || raw.contains(',') {
        return MetadataEdgeMissRangeShape::Complex;
    }
    if raw.starts_with('^') {
        return MetadataEdgeMissRangeShape::Caret;
    }
    if raw.starts_with('~') {
        return MetadataEdgeMissRangeShape::Tilde;
    }
    if raw.starts_with('<') || raw.starts_with('>') || raw.starts_with('=') {
        return MetadataEdgeMissRangeShape::Comparator;
    }
    MetadataEdgeMissRangeShape::Other
}

/// Carrier for the per-pass mutable state. Keeps the dispatch loop
/// readable by bundling the four coupled collections into one place.
pub(super) struct ResolveState {
    /// Root deps from `package.json`. Stored so we can reconstruct
    /// each root edge's range when seeding.
    pub(super) root_deps: HashMap<String, String>,
    /// Edge work queue. Drained by the main loop.
    pub(super) task_queue: VecDeque<Edge>,
    /// Resolved nodes indexed by canonical → list of `(version,
    /// node_id)` pairs. When an edge wants the same
    /// canonical, we walk this list looking for an existing version
    /// whose range satisfies; reuse if found, else allocate a new
    /// node and append. Per-canonical lists are tiny in practice
    /// (1-2 entries even on big trees), so the linear scan is cheap.
    pub(super) resolved: AHashMap<CanonicalKey, Vec<(NpmVersion, NodeId)>>,
    /// Resolved nodes in declaration order. `nodes[i].id == i`.
    pub(super) nodes: Vec<ResolvedNodeBuilder>,
    /// Set of `(canonical, version)` pairs whose declared deps have
    /// already been enqueued as edges. Prevents re-enqueueing the
    /// same package@version's children when a second parent reuses
    /// the existing node. Different versions of the same canonical
    /// each get their OWN entry here because their dep lists are
    /// version-specific.
    pub(super) children_enqueued: AHashSet<(CanonicalKey, NpmVersion)>,
    /// Count of optional deps skipped because no platform-compatible version
    /// satisfied the declared range. Surfaced in `ResolveResult.platform_skipped`
    /// for the install pipeline's `--json` output.
    pub(super) platform_skipped: usize,
    /// Root-level npm alias map. Populated during [`Self::seed_root_edges`]
    /// when a root dep declares `"local": "npm:target@range"`: keyed by
    /// `local` (the alias name the consumer wrote), valued by `target` (the
    /// real registry identity). Drained into `ResolveResult.root_aliases` at
    /// the end of each resolver arm so the install pipeline can build
    /// `node_modules/<local>/` symlinks pointing at the target's content.
    pub(super) root_aliases: HashMap<String, String>,
    /// Parsed override set. [`process_edge`] consults
    /// `overrides.find_match` against (canonical, natural_version,
    /// parent_ctx) for every edge whose canonical satisfies a non-empty
    /// range; on hit, [`apply_override_target_greedy`] produces the forced
    /// version and an [`OverrideHit`] is recorded. `take_hits()` drains the
    /// trace into `ResolveResult.applied_overrides` at the tail of each
    /// resolver arm.
    pub(super) overrides: OverrideSet,
    /// Per-consumer record of every `peerDependencies` entry observed during
    /// the walk. **Collected here, never enqueued onto [`Self::task_queue`].**
    /// Peers are intentionally distinct from regular deps: they map to
    /// `ResolvedPackage.peers` (not `dependencies`), and the v2 store's
    /// graph-key derivation depends on that separation — peer pinning is
    /// folded into the graph key so two installs with the same dep tree but
    /// different peer ranges produce distinct `links/<key>/` entries. If we
    /// silently smuggled peers in as `n.children` edges, peer-divergent
    /// installs would share a single link entry and contaminate each other's
    /// `node_modules/`.
    pub(super) peer_requirements: Vec<PeerRequirement>,
    /// Canonical names of packages the peer-drain pass synthesized as
    /// ambient root-scoped installs. Drained into
    /// `ResolveResult.ambient_peer_installs` at each arm's tail. The install
    /// pipeline reads this set to surface ambient peers at the project's
    /// `node_modules/<name>/` top level — without it, the auto-installed peer
    /// extracts into the global store but never gets a project-side symlink.
    ///
    /// Sorted alphabetically before drain for deterministic output.
    pub(super) ambient_peer_installs: Vec<String>,
    /// Peer-group conflicts the drain resolved best-effort. Each entry
    /// corresponds to one canonical whose required consumer ranges were
    /// pairwise-incompatible: lpm picked the version satisfying the most
    /// consumers, recorded the unsatisfied ones here, and continued. Drained
    /// into `ResolveResult.peer_conflicts` at the arm tail; install pipeline
    /// prints a single warning per entry. Empty when no peer group needed
    /// best-effort fallback.
    pub(super) peer_conflicts: Vec<PeerConflictReport>,
    /// Per-run peer resolution cache. Keyed by peer canonical plus a
    /// stable hash of the sorted parent peer context so repeated peer-drain
    /// passes don't recompute the same manifest decision.
    pub(super) peer_resolution_cache:
        dashmap::DashMap<PeerResolutionCacheKey, CachedPeerResolution>,
    pub(super) include_optional_dependencies: bool,
    pub(super) policy: ResolverPolicy,
    pub(super) work_stats: ResolveWorkStats,
    selected_package_tx: Option<tokio::sync::mpsc::UnboundedSender<SelectedPackageEvent>>,
}

/// In-flight resolved node — accumulated during the loop, finalized
/// at `into_resolved_packages` time.
#[derive(Debug)]
pub(super) struct ResolvedNodeBuilder {
    pub(super) canonical: CanonicalKey,
    pub(super) version: NpmVersion,
    pub(super) optional: bool,
    /// Edges going OUT of this node: (local_name, child_node_id).
    pub(super) children: Vec<(String, NodeId)>,
}

impl ResolveState {
    #[cfg(test)]
    pub(super) fn new(root_deps: HashMap<String, String>, overrides: OverrideSet) -> Self {
        Self::new_with_options(root_deps, overrides, true)
    }

    #[cfg(test)]
    pub(super) fn new_with_options(
        root_deps: HashMap<String, String>,
        overrides: OverrideSet,
        include_optional_dependencies: bool,
    ) -> Self {
        Self::new_with_options_and_policy(
            root_deps,
            overrides,
            include_optional_dependencies,
            ResolverPolicy::default(),
        )
    }

    pub(super) fn new_with_options_and_policy(
        root_deps: HashMap<String, String>,
        overrides: OverrideSet,
        include_optional_dependencies: bool,
        policy: ResolverPolicy,
    ) -> Self {
        ResolveState {
            root_deps,
            task_queue: VecDeque::with_capacity(256),
            resolved: AHashMap::with_capacity(512),
            nodes: Vec::with_capacity(512),
            children_enqueued: AHashSet::with_capacity(512),
            platform_skipped: 0,
            root_aliases: HashMap::new(),
            overrides,
            // Most installs declare zero peers at any given level. Even
            // bench/fixture-large produces ~10s of total peer entries
            // across 250+ packages. Start small; Vec::push amortizes.
            peer_requirements: Vec::new(),
            // Typically 0 (most installs don't need ambient peer
            // synthesis). Allocated lazily on first push.
            ambient_peer_installs: Vec::new(),
            // Typically 0 (most installs have a clean peer graph).
            // Allocated lazily on first conflict.
            peer_conflicts: Vec::new(),
            peer_resolution_cache: dashmap::DashMap::with_capacity(64),
            include_optional_dependencies,
            policy,
            work_stats: ResolveWorkStats::default(),
            selected_package_tx: None,
        }
    }

    pub(super) fn set_selected_package_tx(
        &mut self,
        tx: Option<tokio::sync::mpsc::UnboundedSender<SelectedPackageEvent>>,
    ) {
        self.selected_package_tx = tx;
    }

    pub(super) fn emit_selected_package(
        &self,
        canonical: &CanonicalKey,
        version: &NpmVersion,
        info: &CachedPackageInfo,
        optional: bool,
    ) {
        let Some(tx) = &self.selected_package_tx else {
            return;
        };
        let version = version.to_string();
        let event = SelectedPackageEvent {
            name: canonical.to_string(),
            version: version.clone(),
            is_lpm: matches!(canonical, CanonicalKey::Lpm { .. }),
            tarball_url: info
                .dist
                .get(&version)
                .and_then(|dist| dist.tarball_url.clone()),
            integrity: info
                .dist
                .get(&version)
                .and_then(|dist| dist.integrity.clone()),
            platform: info.platform.get(&version).cloned(),
            optional,
        };
        let _ = tx.send(event);
    }

    /// Seed the queue with one Edge per root dependency. The pseudo-node
    /// with id=0 represents the project root; its children are tracked
    /// in the resolved-tree edges but it has no version of its own and
    /// is filtered out at `into_resolved_packages` time, matching
    /// PubGrub's `format_solution` (which filters `pkg.is_root()`).
    pub(super) fn seed_root_edges(&mut self) -> Result<(), ResolveError> {
        // Insert the root pseudo-node so child edges have a parent id.
        // It carries a sentinel canonical (`Root`) and a placeholder
        // version. Filtered out at `into_resolved_packages`.
        self.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::Root,
            version: NpmVersion::new(0, 0, 0),
            optional: false,
            children: Vec::new(),
        });
        // Root carries a sentinel canonical; it's never queried by an
        // edge's `process_edge` (no edge has CanonicalKey::Root as its
        // target). Kept in the map for symmetry with the rest of the
        // resolved-tree shape.
        self.resolved
            .insert(CanonicalKey::Root, vec![(NpmVersion::new(0, 0, 0), 0)]);
        // Root-level alias rewrite: if the consumer's package.json declares
        // `"local": "npm:target@range"`, the resolver must (a) key the
        // canonical on `target` (the real registry identity) so metadata
        // fetch + version resolution hit the right package, (b) parse the
        // inner range, and (c) record `local → target` in
        // `self.root_aliases` so the install pipeline can build
        // `node_modules/<local>/` from the target's content.
        let mut entries: Vec<_> = self.root_deps.iter().collect();
        entries.sort_by_key(|(name, _)| *name);
        for (name, range_str) in entries {
            let (canonical_name, effective_range) = match crate::ranges::parse_npm_alias(range_str)
            {
                Some(alias) => {
                    self.root_aliases.insert(name.clone(), alias.target.clone());
                    (alias.target, alias.range)
                }
                None => (name.clone(), range_str.clone()),
            };
            let canonical = CanonicalKey::from_dep_name(&canonical_name);
            // `workspace:<rest>` must be rewritten upstream by
            // `lpm-workspace` before reaching the resolver.
            // If a raw `workspace:` slips through (e.g., a future
            // refactor drops the upstream layer or a manifest is
            // hand-edited), `NpmRange::parse` would fail with an
            // opaque semver error. This guard surfaces the actual
            // diagnosis to the maintainer.
            if is_workspace_specifier(&effective_range) {
                return Err(ResolveError::Internal(format!(
                    "root dep {name}: range '{effective_range}' uses the \
                     `workspace:` protocol, which must be resolved by \
                     `lpm-workspace` before reaching the resolver. This is \
                     an internal bug — please file an issue at \
                     https://github.com/lpm-dev/rust-client/issues"
                )));
            }
            let range = NpmRange::parse(&effective_range).map_err(|e| {
                ResolveError::Internal(format!("failed to parse range for root dep {name}: {e}"))
            })?;
            self.task_queue.push_back(Edge {
                parent: 0,
                local_name: name.clone(),
                canonical,
                range,
                behavior: DepBehavior {
                    required: true,
                    peer: false,
                    optional: false,
                },
            });
        }
        Ok(())
    }

    /// Convert the in-flight builders into the public
    /// `Vec<ResolvedPackage>`. Mirrors `format_solution`.
    pub(super) fn into_resolved_packages(
        self,
        cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
    ) -> Vec<ResolvedPackage> {
        // Build node-id → version-string lookup so child edges can
        // be resolved to the child's selected version regardless of
        // aliasing (alias rewriting already happened at edge-creation
        // time, so children[i].1 is always the correct node id).
        let id_to_version: Vec<String> = self.nodes.iter().map(|n| n.version.to_string()).collect();

        // canonical-name → resolved-version lookup for peer resolution.
        // Mirrors `format_solution`'s peer-candidate lookup. Built from the
        // same node table (filtered to non-root) so peer name-lookups
        // intersect the active install set. `CanonicalKey`'s Display impl
        // emits the canonical-name form (`@lpm.dev/owner.name` or `react`),
        // matching how `peerDependencies` keys are spelled in package.json.
        let resolved_by_canonical: HashMap<String, Vec<(Option<String>, String)>> = self
            .nodes
            .iter()
            .filter(|n| !matches!(n.canonical, CanonicalKey::Root))
            .fold(HashMap::new(), |mut acc, n| {
                acc.entry(n.canonical.to_string())
                    .or_default()
                    .push((None, n.version.to_string()));
                acc
            });

        let mut out: Vec<ResolvedPackage> = self
            .nodes
            .into_iter()
            .enumerate()
            .filter(|(_, n)| !matches!(n.canonical, CanonicalKey::Root))
            .map(|(_, n)| {
                let pkg = canonical_to_resolver_package(&n.canonical);
                let ver_str = n.version.to_string();

                let cached_aliases: HashMap<String, String> = cache
                    .get(&n.canonical)
                    .and_then(|info| info.aliases.get(&ver_str))
                    .cloned()
                    .unwrap_or_default();

                // Sort each parent's dependency list by local_name for
                // byte-identical lockfile output across resolver arms.
                // On the walker arm, n.children is already alphabetic by
                // virtue of `enqueue_child_deps` pre-sorting + FIFO
                // task_queue + serial process_edge. Under fusion, parked
                // edges resume in manifest-arrival order so n.children's
                // insertion order is non-deterministic w.r.t. names. The
                // sort makes the alphabetic invariant explicit and
                // arm-independent.
                let mut dependencies: Vec<(String, String)> = n
                    .children
                    .iter()
                    .map(|(local, child_id)| {
                        let child_ver = id_to_version[*child_id as usize].clone();
                        (local.clone(), child_ver)
                    })
                    .collect();
                dependencies.sort_by(|a, b| a.0.cmp(&b.0));

                let alive_locals: HashSet<&String> = dependencies.iter().map(|(l, _)| l).collect();
                let aliases: HashMap<String, String> = cached_aliases
                    .iter()
                    .filter(|(local, _)| alive_locals.contains(local))
                    .map(|(l, t)| (l.clone(), t.clone()))
                    .collect();

                let (tarball_url, integrity) = cache
                    .get(&n.canonical)
                    .and_then(|info| info.dist.get(&ver_str))
                    .map(|d| (d.tarball_url.clone(), d.integrity.clone()))
                    .unwrap_or_default();
                let platform = cache
                    .get(&n.canonical)
                    .and_then(|info| info.platform.get(&ver_str))
                    .cloned();

                // Surface resolved peers per package so the v2 GraphKey
                // can fold them in. The resolved-versions lookup is built
                // from the same node table.
                let peers: Vec<(String, String)> = cache
                    .get(&n.canonical)
                    .and_then(|info| info.peer_deps.get(&ver_str))
                    .map(|peer_deps| {
                        let mut out: Vec<(String, String)> = peer_deps
                            .iter()
                            .filter_map(|(peer_name, peer_range)| {
                                let parsed_range = NpmRange::parse(peer_range).ok();
                                resolve_peer_binding_version(
                                    &pkg,
                                    peer_name,
                                    parsed_range.as_ref(),
                                    &resolved_by_canonical,
                                )
                                .map(|(ver, _)| (peer_name.clone(), ver.clone()))
                            })
                            .collect();
                        out.sort_by(|a, b| a.0.cmp(&b.0));
                        out
                    })
                    .unwrap_or_default();

                ResolvedPackage {
                    package: pkg,
                    version: n.version,
                    dependencies,
                    aliases,
                    peers,
                    tarball_url,
                    integrity,
                    platform,
                    optional: n.optional,
                }
            })
            .collect();

        crate::resolve::dedupe_peer_superset_packages(&mut out);

        // Match `format_solution`'s deterministic order so lockfile
        // serialization is stable regardless of resolution order.
        //
        // Secondary sort by version. `ResolverPackage`'s `Display` impl
        // drops the version (Npm prints just `name`), so two distinct
        // ResolvedPackages for `debug@2.6.9` and `debug@4.4.3` tie under
        // the primary key. Without a tiebreaker, the stable sort preserves
        // the original Vec order — which depends on `state.resolved`'s
        // insertion order, which under fusion follows manifest-arrival order
        // rather than walker-arm alphabetic-BFS order. Sorting by version on
        // tie makes the total order deterministic and arm-independent.
        out.sort_by_cached_key(|pkg| (pkg.package.to_string(), pkg.version.clone()));
        out
    }

    pub(super) fn edge_resolution_context(
        &self,
        edge: &Edge,
        kind: ResolutionFailureKind,
        reason: String,
        available_versions: Option<usize>,
        newest_version: Option<String>,
    ) -> ResolutionErrorContext {
        ResolutionErrorContext {
            package: edge.canonical.to_string(),
            requested: edge.range.to_string(),
            dependency: edge.local_name.clone(),
            required_by: self.edge_required_by(edge),
            kind,
            reason,
            available_versions,
            newest_version,
            derivation: None,
        }
    }

    fn edge_required_by(&self, edge: &Edge) -> Option<String> {
        let parent = self.nodes.get(edge.parent as usize)?;
        match &parent.canonical {
            CanonicalKey::Root => Some("project root".to_string()),
            _ => Some(format!("{}@{}", parent.canonical, parent.version)),
        }
    }
}

pub(super) fn selected_package_cardinality(packages: &[ResolvedPackage]) -> (u64, u64, u64) {
    let mut unique = HashSet::with_capacity(packages.len());
    for package in packages {
        unique.insert(package.package.to_string());
    }
    let selected = packages.len() as u64;
    let unique_count = unique.len() as u64;
    (
        selected,
        unique_count,
        selected.saturating_sub(unique_count),
    )
}

/// Convert a `CanonicalKey` back to a `ResolverPackage` for the
/// public output. Greedy output currently emits non-split
/// (`context: None`) packages; duplicate canonicals remain distinct
/// by resolved version.
fn canonical_to_resolver_package(key: &CanonicalKey) -> ResolverPackage {
    match key {
        CanonicalKey::Root => ResolverPackage::Root,
        CanonicalKey::Lpm { owner, name } => ResolverPackage::Lpm {
            owner: owner.clone(),
            name: name.clone(),
            context: None,
        },
        CanonicalKey::Npm { name } => ResolverPackage::Npm {
            name: name.clone(),
            context: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_info() -> CachedPackageInfo {
        CachedPackageInfo {
            modified: None,
            modified_unix: None,
            trust_metadata_complete: false,
            versions: vec![NpmVersion::parse("1.0.0").expect("valid version")],
            deps: HashMap::new(),
            peer_deps: HashMap::new(),
            optional_dep_names: HashMap::new(),
            optional_peer_names: HashMap::new(),
            bundled_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    fn shape(raw: &str) -> MetadataEdgeMissRangeShape {
        metadata_edge_miss_range_shape(&NpmRange::parse(raw).expect("valid test range"))
    }

    #[test]
    fn metadata_edge_miss_range_shape_classifies_exact_versions() {
        assert_eq!(shape("1.2.3"), MetadataEdgeMissRangeShape::Exact);
    }

    #[test]
    fn metadata_edge_miss_range_shape_classifies_latest_as_star() {
        assert_eq!(shape("latest"), MetadataEdgeMissRangeShape::Star);
    }

    #[test]
    fn metadata_edge_miss_range_shape_classifies_common_range_operators() {
        assert_eq!(shape("^1.2.3"), MetadataEdgeMissRangeShape::Caret);
        assert_eq!(shape("~1.2.3"), MetadataEdgeMissRangeShape::Tilde);
        assert_eq!(shape(">=1.2.3"), MetadataEdgeMissRangeShape::Comparator);
        assert_eq!(shape(">=1.0.0 <2.0.0"), MetadataEdgeMissRangeShape::Complex);
        assert_eq!(
            shape("^1.0.0 || ^2.0.0"),
            MetadataEdgeMissRangeShape::Complex
        );
    }

    #[test]
    fn metadata_edge_miss_latest_records_version_doc_policy_eligibility_without_latest_tag() {
        let mut stats = ResolveWorkStats::default();
        let route_table = RouteTable::from_mode_only(RouteMode::Direct);
        let canonical = CanonicalKey::npm("left-pad");
        let range = NpmRange::parse("1.0.0").expect("valid range");
        let info = empty_info();

        let policy = ResolverPolicy::default();
        stats.record_metadata_edge_miss_latest(MetadataEdgeMissLatest {
            canonical: &canonical,
            range: &range,
            info: &info,
            latest_version: None,
            route_table: &route_table,
            policy: &policy,
            compare_policy_pick: true,
        });

        assert_eq!(
            stats.metadata_edge_miss_version_doc_policy_eligible_count,
            1
        );
        assert_eq!(
            stats.metadata_edge_miss_version_doc_policy_eligible_direct_count,
            1
        );
        assert_eq!(stats.metadata_edge_miss_latest_known_count, 0);
    }

    #[test]
    fn metadata_edge_miss_latest_skips_policy_pick_match_when_comparison_disabled() {
        let mut stats = ResolveWorkStats::default();
        let route_table = RouteTable::from_mode_only(RouteMode::Direct);
        let canonical = CanonicalKey::npm("left-pad");
        let range = NpmRange::parse("^1.0.0").expect("valid range");
        let info = empty_info();
        let latest = NpmVersion::parse("1.0.0").expect("valid version");

        let policy = ResolverPolicy::default();
        stats.record_metadata_edge_miss_latest(MetadataEdgeMissLatest {
            canonical: &canonical,
            range: &range,
            info: &info,
            latest_version: Some(&latest),
            route_table: &route_table,
            policy: &policy,
            compare_policy_pick: false,
        });

        assert_eq!(stats.metadata_edge_miss_latest_known_count, 1);
        assert_eq!(stats.metadata_edge_miss_latest_satisfies_count, 1);
        assert_eq!(stats.metadata_edge_miss_latest_matches_pick_count, 0);
    }
}
