use super::peer::{CachedPeerResolution, PeerResolutionCacheKey};
use super::prelude::*;
use super::types::{DepBehavior, Edge, NodeId, PeerConflictReport, PeerRequirement};
use super::version::is_workspace_specifier;
use super::version::{VersionPick, find_best_version_with_policy_unprofiled};
use crate::resolve::SelectedPackageEvent;

#[derive(Debug, Default)]
pub(super) struct PeerWorkStats {
    non_empty_pass_count: u64,
    requirement_count: u64,
    seen_requirements: AHashSet<(NodeId, String)>,
    group_count: u64,
    already_satisfied_group_count: u64,
    classified_group_count: u64,
    skipped_opt_out_group_count: u64,
    resolution_cache_hit_count: u64,
    resolution_cache_miss_count: u64,
    manifest_lookup_count: u64,
    manifest_wait_ns: u64,
    processing_ns: u64,
    synthesized_edge_count: u64,
}

pub(super) struct PeerPassMeasurement {
    started: std::time::Instant,
    manifest_wait_ns_before: u64,
}

impl PeerWorkStats {
    pub(super) fn begin_pass(&mut self, pending: &[PeerRequirement]) -> PeerPassMeasurement {
        self.non_empty_pass_count = self.non_empty_pass_count.saturating_add(1);
        self.requirement_count = self
            .requirement_count
            .saturating_add(u64::try_from(pending.len()).unwrap_or(u64::MAX));
        for requirement in pending {
            self.seen_requirements
                .insert((requirement.consumer, requirement.peer_name.clone()));
        }
        PeerPassMeasurement {
            started: std::time::Instant::now(),
            manifest_wait_ns_before: self.manifest_wait_ns,
        }
    }

    pub(super) fn finish_pass(&mut self, measurement: PeerPassMeasurement) {
        let total_ns = duration_ns(measurement.started.elapsed());
        let manifest_wait_ns = self
            .manifest_wait_ns
            .saturating_sub(measurement.manifest_wait_ns_before);
        self.processing_ns = self
            .processing_ns
            .saturating_add(total_ns.saturating_sub(manifest_wait_ns));
    }

    pub(super) fn record_group(&mut self) {
        self.group_count = self.group_count.saturating_add(1);
    }

    pub(super) fn record_already_satisfied_group(&mut self) {
        self.already_satisfied_group_count = self.already_satisfied_group_count.saturating_add(1);
    }

    pub(super) fn record_classified_group(&mut self) {
        self.classified_group_count = self.classified_group_count.saturating_add(1);
    }

    pub(super) fn record_skipped_opt_out_group(&mut self) {
        self.skipped_opt_out_group_count = self.skipped_opt_out_group_count.saturating_add(1);
    }

    pub(super) fn record_resolution_cache_hit(&mut self) {
        self.resolution_cache_hit_count = self.resolution_cache_hit_count.saturating_add(1);
    }

    pub(super) fn record_resolution_cache_miss(&mut self) {
        self.resolution_cache_miss_count = self.resolution_cache_miss_count.saturating_add(1);
    }

    pub(super) fn record_manifest_wait(&mut self, elapsed: std::time::Duration) {
        self.manifest_lookup_count = self.manifest_lookup_count.saturating_add(1);
        self.manifest_wait_ns = self.manifest_wait_ns.saturating_add(duration_ns(elapsed));
    }

    pub(super) fn record_synthesized_edge(&mut self) {
        self.synthesized_edge_count = self.synthesized_edge_count.saturating_add(1);
    }

    pub(super) fn snapshot(&self) -> crate::resolve::PeerStageTiming {
        crate::resolve::PeerStageTiming {
            non_empty_pass_count: self.non_empty_pass_count,
            requirement_count: self.requirement_count,
            unique_requirement_count: u64::try_from(self.seen_requirements.len())
                .unwrap_or(u64::MAX),
            group_count: self.group_count,
            already_satisfied_group_count: self.already_satisfied_group_count,
            classified_group_count: self.classified_group_count,
            skipped_opt_out_group_count: self.skipped_opt_out_group_count,
            resolution_cache_hit_count: self.resolution_cache_hit_count,
            resolution_cache_miss_count: self.resolution_cache_miss_count,
            manifest_lookup_count: self.manifest_lookup_count,
            manifest_wait_ns: self.manifest_wait_ns,
            processing_ns: self.processing_ns,
            synthesized_edge_count: self.synthesized_edge_count,
        }
    }
}

fn duration_ns(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

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

pub(super) struct PendingRootConstraints {
    remaining: AHashMap<CanonicalKey, usize>,
    deferred: AHashMap<CanonicalKey, Vec<Edge>>,
}

impl PendingRootConstraints {
    pub(super) fn from_task_queue(task_queue: &VecDeque<Edge>) -> Self {
        let mut remaining = AHashMap::with_capacity(task_queue.len());
        for edge in task_queue.iter().filter(|edge| edge.parent == 0) {
            *remaining.entry(edge.canonical.clone()).or_insert(0) += 1;
        }
        Self {
            remaining,
            deferred: AHashMap::new(),
        }
    }

    pub(super) fn defer_if_root_pending(&mut self, edge: Edge) -> Option<Edge> {
        if edge.parent == 0
            || self.remaining.is_empty()
            || !self.remaining.contains_key(&edge.canonical)
        {
            return Some(edge);
        }
        self.deferred
            .entry(edge.canonical.clone())
            .or_default()
            .push(edge);
        None
    }

    pub(super) fn complete_root_edge(&mut self, edge: &Edge, task_queue: &mut VecDeque<Edge>) {
        if edge.parent != 0 {
            return;
        }
        let Some(count) = self.remaining.get_mut(&edge.canonical) else {
            return;
        };
        *count -= 1;
        if *count != 0 {
            return;
        }
        self.remaining.remove(&edge.canonical);
        if let Some(edges) = self.deferred.remove(&edge.canonical) {
            for deferred in edges.into_iter().rev() {
                task_queue.push_front(deferred);
            }
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.remaining.is_empty() && self.deferred.is_empty()
    }
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
    if raw == "*" || raw == "latest" {
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
    pub(super) optional_root_names: HashSet<String>,
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
    /// parent_ctx) for every edge with a natural selection; on hit,
    /// [`apply_override_target_greedy`] produces the forced version and an
    /// [`OverrideHit`] is recorded if that version changed. `take_hits()`
    /// drains the trace into `ResolveResult.applied_overrides` at the tail of
    /// each resolver arm.
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
    pub(super) peer_bindings: AHashMap<NodeId, AHashMap<String, NodeId>>,
    pub(super) pending_peer_bindings: AHashMap<(CanonicalKey, NpmVersion), Vec<(NodeId, String)>>,
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
    pub(super) peer_work_stats: PeerWorkStats,
    selected_package_tx: Option<tokio::sync::mpsc::Sender<SelectedPackageEvent>>,
    pending_selected_packages: VecDeque<SelectedPackageEvent>,
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

    #[cfg(test)]
    pub(super) fn new_with_options_and_policy(
        root_deps: HashMap<String, String>,
        overrides: OverrideSet,
        include_optional_dependencies: bool,
        policy: ResolverPolicy,
    ) -> Self {
        Self::new_with_root_dependencies_and_policy(
            crate::resolve::RootDependencies::required(root_deps),
            overrides,
            include_optional_dependencies,
            policy,
        )
    }

    pub(super) fn new_with_root_dependencies_and_policy(
        root_dependencies: crate::resolve::RootDependencies,
        overrides: OverrideSet,
        include_optional_dependencies: bool,
        policy: ResolverPolicy,
    ) -> Self {
        let crate::resolve::RootDependencies {
            dependencies: root_deps,
            optional_names: optional_root_names,
        } = root_dependencies;
        ResolveState {
            root_deps,
            optional_root_names,
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
            peer_bindings: AHashMap::new(),
            pending_peer_bindings: AHashMap::new(),
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
            peer_work_stats: PeerWorkStats::default(),
            selected_package_tx: None,
            pending_selected_packages: VecDeque::new(),
        }
    }

    pub(super) fn set_selected_package_tx(
        &mut self,
        tx: Option<tokio::sync::mpsc::Sender<SelectedPackageEvent>>,
    ) {
        self.selected_package_tx = tx;
    }

    pub(super) fn record_exact_peer_binding(
        &mut self,
        consumer: NodeId,
        local_name: String,
        target: NodeId,
    ) {
        self.peer_bindings
            .entry(consumer)
            .or_default()
            .insert(local_name, target);
    }

    pub(super) fn record_pending_peer_binding(
        &mut self,
        consumer: NodeId,
        local_name: String,
        canonical: CanonicalKey,
        version: NpmVersion,
    ) {
        self.pending_peer_bindings
            .entry((canonical, version))
            .or_default()
            .push((consumer, local_name));
    }

    pub(super) fn resolve_pending_peer_bindings(
        &mut self,
        canonical: &CanonicalKey,
        version: &NpmVersion,
        target: NodeId,
    ) {
        let Some(bindings) = self
            .pending_peer_bindings
            .remove(&(canonical.clone(), version.clone()))
        else {
            return;
        };
        for (consumer, local_name) in bindings {
            self.record_exact_peer_binding(consumer, local_name, target);
        }
    }

    pub(super) fn emit_selected_package(
        &mut self,
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
            tarball_url: info.tarball_url(&version).map(str::to_owned),
            integrity: info.integrity(&version).map(str::to_owned),
            unpacked_size: info.unpacked_size(&version),
            platform: info.platform(&version),
            node_engine: info.node_engine(&version).map(str::to_owned),
            optional,
        };
        match tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                self.pending_selected_packages.push_back(event);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    pub(super) async fn flush_selected_packages(&mut self) {
        let Some(tx) = self.selected_package_tx.as_ref() else {
            self.pending_selected_packages.clear();
            return;
        };
        while let Some(event) = self.pending_selected_packages.pop_front() {
            if tx.send(event).await.is_err() {
                self.pending_selected_packages.clear();
                break;
            }
        }
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
            let optional = self.optional_root_names.contains(name);
            if optional && !self.include_optional_dependencies {
                continue;
            }
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
            let range = NpmRange::parse_registry_spec(&effective_range).map_err(|e| {
                ResolveError::Internal(format!("failed to parse range for root dep {name}: {e}"))
            })?;
            self.task_queue.push_back(Edge {
                parent: 0,
                local_name: name.clone(),
                canonical,
                range,
                behavior: DepBehavior {
                    required: !optional,
                    peer: false,
                    optional,
                },
            });
        }
        Ok(())
    }

    pub(super) fn root_resolutions(&self) -> HashMap<String, RootResolution> {
        let Some(root) = self.nodes.first() else {
            return HashMap::new();
        };
        let mut resolutions = HashMap::with_capacity(self.root_deps.len());
        for (local_name, node_id) in &root.children {
            let is_manifest_root = self.root_deps.contains_key(local_name);
            let is_ambient_peer = self
                .ambient_peer_installs
                .iter()
                .any(|peer| peer == local_name);
            if (!is_manifest_root && !is_ambient_peer) || resolutions.contains_key(local_name) {
                continue;
            }
            let Some(selected) = self.nodes.get(*node_id as usize) else {
                continue;
            };
            resolutions.insert(
                local_name.clone(),
                RootResolution {
                    target: lpm_common::ResolutionNodeId::new(*node_id),
                    package: selected.canonical.to_string(),
                    version: selected.version.to_string(),
                },
            );
        }
        resolutions
    }

    /// Convert the in-flight builders into the public
    /// `Vec<ResolvedPackage>`. Mirrors `format_solution`.
    pub(super) fn into_resolved_packages(
        self,
        cache: &HashMap<CanonicalKey, Arc<CachedPackageInfo>>,
        _root_aliases: &HashMap<String, String>,
    ) -> Vec<ResolvedPackage> {
        let root_resolutions = self.root_resolutions();
        let root_dependencies = crate::resolve::RootDependencies::with_optional_names(
            self.root_deps,
            self.optional_root_names,
        );
        let peer_bindings = self.peer_bindings;
        let nodes = self.nodes;
        // Build node-id → version-string lookup so child edges can
        // be resolved to the child's selected version regardless of
        // aliasing (alias rewriting already happened at edge-creation
        // time, so children[i].1 is always the correct node id).
        let id_to_version: Vec<String> = nodes.iter().map(|n| n.version.to_string()).collect();

        let mut out: Vec<ResolvedPackage> = nodes
            .into_iter()
            .enumerate()
            .filter(|(_, n)| !matches!(n.canonical, CanonicalKey::Root))
            .map(|(node_index, n)| {
                let pkg = canonical_to_resolver_package(&n.canonical);
                let ver_str = n.version.to_string();
                let selected_peer_bindings = peer_bindings.get(&(node_index as NodeId));
                let resolution_id = lpm_common::ResolutionNodeId::new(node_index as NodeId);

                let cached_aliases: HashMap<String, String> = cache
                    .get(&n.canonical)
                    .map(|info| info.dependency_aliases(&ver_str))
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
                let dependency_targets = n
                    .children
                    .iter()
                    .map(|(local, child_id)| {
                        (local.clone(), lpm_common::ResolutionNodeId::new(*child_id))
                    })
                    .collect();
                let optional_dependencies = cache
                    .get(&n.canonical)
                    .map(|info| info.optional_dependency_names(&ver_str))
                    .unwrap_or_default();

                let alive_locals: HashSet<&String> = dependencies.iter().map(|(l, _)| l).collect();
                let aliases: HashMap<String, String> = cached_aliases
                    .iter()
                    .filter(|(local, _)| alive_locals.contains(local))
                    .map(|(l, t)| (l.clone(), t.clone()))
                    .collect();

                let (tarball_url, integrity) = cache.get(&n.canonical).map_or_else(
                    || (None, None),
                    |info| {
                        (
                            info.tarball_url(&ver_str).map(str::to_owned),
                            info.integrity(&ver_str).map(str::to_owned),
                        )
                    },
                );
                let platform = cache
                    .get(&n.canonical)
                    .and_then(|info| info.platform(&ver_str));
                let node_engine = cache
                    .get(&n.canonical)
                    .and_then(|info| info.node_engine(&ver_str).map(str::to_owned));

                // Surface resolved peers per package so the v2 GraphKey
                // can fold them in. The resolved-versions lookup is built
                // from the same node table.
                let peers: Vec<lpm_common::PeerEdge> = cache
                    .get(&n.canonical)
                    .and_then(|info| info.peer_dependencies(&ver_str))
                    .map(|peer_dependencies| {
                        let mut out: Vec<lpm_common::PeerEdge> = peer_dependencies
                            .filter_map(|peer| {
                                let peer_name = peer.name;
                                let target_name = peer.alias.unwrap_or(peer_name);
                                if let Some(&target_id) = selected_peer_bindings
                                    .and_then(|bindings| bindings.get(peer_name))
                                {
                                    let version = &id_to_version[target_id as usize];
                                    return Some(lpm_common::PeerEdge::registry(
                                        peer_name,
                                        target_name,
                                        version,
                                    ));
                                }
                                None
                            })
                            .collect();
                        out.sort_by(|a, b| a.local_name.cmp(&b.local_name));
                        out
                    })
                    .unwrap_or_default();
                let peer_targets = selected_peer_bindings
                    .into_iter()
                    .flat_map(|bindings| bindings.iter())
                    .map(|(local_name, target)| {
                        (
                            local_name.clone(),
                            lpm_common::ResolutionNodeId::new(*target),
                        )
                    })
                    .collect();

                ResolvedPackage {
                    resolution_id,
                    package: pkg,
                    version: n.version,
                    dependencies,
                    dependency_targets,
                    optional_dependencies,
                    aliases,
                    peers,
                    peer_targets,
                    tarball_url,
                    integrity,
                    platform,
                    node_engine,
                    optional: n.optional,
                }
            })
            .collect();

        crate::resolve::mark_optional_reachability(&mut out, &root_dependencies, &root_resolutions);

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
        CachedPackageInfo::from_manifest_versions(
            None,
            false,
            true,
            HashSet::new(),
            HashSet::new(),
            true,
            None,
            vec![crate::provider::ManifestVersion {
                version: NpmVersion::parse("1.0.0").expect("valid version"),
                dependencies: Vec::new(),
                peer_dependencies: Vec::new(),
                node_engine: None,
                platform: None,
                dist: crate::provider::CachedDistInfo::default(),
            }],
        )
    }

    fn shape(raw: &str) -> MetadataEdgeMissRangeShape {
        metadata_edge_miss_range_shape(&NpmRange::parse(raw).expect("valid test range"))
    }

    fn root_edge(name: &str) -> Edge {
        Edge {
            parent: 0,
            local_name: name.to_string(),
            canonical: CanonicalKey::npm(name),
            range: NpmRange::parse("*").expect("valid range"),
            behavior: DepBehavior {
                required: true,
                peer: false,
                optional: false,
            },
        }
    }

    #[test]
    fn pending_root_constraints_ignore_synthetic_root_edges() {
        let initial = root_edge("initial-root");
        let mut queue = VecDeque::from([initial.clone()]);
        let mut pending = PendingRootConstraints::from_task_queue(&queue);

        pending.complete_root_edge(&root_edge("synthetic-peer"), &mut queue);
        assert!(
            !pending.is_empty(),
            "an unrelated synthetic root must not release the initial barrier"
        );

        pending.complete_root_edge(&initial, &mut queue);
        assert!(pending.is_empty());
    }

    #[test]
    fn root_resolutions_keep_manifest_selection_when_ambient_peer_uses_same_name() {
        let mut state = ResolveState::new(
            HashMap::from([("peer-host".to_string(), "^1.0.0".to_string())]),
            OverrideSet::empty(),
        );
        state.seed_root_edges().expect("seed root edge");
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("peer-host"),
            version: NpmVersion::parse("1.0.0").expect("valid direct version"),
            optional: false,
            children: Vec::new(),
        });
        state.nodes.push(ResolvedNodeBuilder {
            canonical: CanonicalKey::npm("peer-host"),
            version: NpmVersion::parse("1.1.0").expect("valid ambient version"),
            optional: false,
            children: Vec::new(),
        });
        state.nodes[0].children = vec![("peer-host".to_string(), 1), ("peer-host".to_string(), 2)];

        assert_eq!(
            state.root_resolutions().get("peer-host"),
            Some(&RootResolution {
                target: lpm_common::ResolutionNodeId::new(1),
                package: "peer-host".to_string(),
                version: "1.0.0".to_string(),
            })
        );
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
