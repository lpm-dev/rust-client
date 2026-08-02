use super::prelude::*;

/// Resolver input for dependency edges attached to the resolver's synthetic root.
///
/// Optional names use the manifest's local dependency key, including npm aliases.
#[derive(Debug, Clone, Default)]
pub struct RootDependencies {
    pub(crate) dependencies: HashMap<String, String>,
    pub(crate) optional_names: HashSet<String>,
}

impl RootDependencies {
    /// Builds resolver input where every root edge is required.
    pub fn required(dependencies: HashMap<String, String>) -> Self {
        Self {
            dependencies,
            optional_names: HashSet::new(),
        }
    }

    /// Builds resolver input with the named root edges treated as optional.
    /// Names absent from `dependencies` are discarded.
    pub fn with_optional_names(
        dependencies: HashMap<String, String>,
        mut optional_names: HashSet<String>,
    ) -> Self {
        optional_names.retain(|name| dependencies.contains_key(name));
        Self {
            dependencies,
            optional_names,
        }
    }

    #[inline]
    pub(crate) fn is_optional(&self, local_name: &str) -> bool {
        self.optional_names.contains(local_name)
    }
}

/// A resolved package: name + selected version + its dependencies.
#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub package: ResolverPackage,
    pub version: NpmVersion,
    /// Dependencies of this package: (dep_name_in_parent, resolved_version_string).
    ///
    /// `dep_name_in_parent` is the LOCAL name used in THIS package's
    /// `dependencies` / `optionalDependencies` map. For non-aliased
    /// deps this equals the child's canonical registry name; for
    /// npm-alias deps (e.g., `"strip-ansi-cjs": "npm:strip-ansi@^6"`)
    /// it is the alias key, and the `aliases` map below records the
    /// alias's canonical target name. Keeping the local name as the
    /// edge key means the linker can build `node_modules/<local>/`
    /// directly from the edge without a second lookup.
    pub dependencies: Vec<(String, String)>,
    /// npm-alias edges. Key = `dep_name_in_parent`
    /// from the `dependencies` vec; value = target canonical package
    /// name (what to fetch from the registry + how the `.lpm/` store
    /// entry is keyed). Empty for packages that declare no aliased
    /// deps (the common case). Non-aliased edges are NOT present —
    /// callers compute `aliases.get(local).unwrap_or(local)` to get
    /// the target.
    pub aliases: HashMap<String, String>,
    /// Resolved peers that ARE in scope for this consumer in the
    /// install set. Shape: `(peer_name, resolved_version)` — same
    /// edge shape as `dependencies`, but read from
    /// `peerDependencies` / `peerDependenciesMeta` and intersected
    /// against the install set's resolved versions.
    ///
    /// Sorted by peer_name for deterministic lockfile / GraphKey
    /// hashing. Empty when this package declares no peers OR when
    /// every declared peer is missing from the install set
    /// (`check_unmet_peers` surfaces those as `PeerWarning`s).
    ///
    /// The v2 GraphKey folds these in so two projects sharing the
    /// same edge graph but different peer pinning produce distinct
    /// keys. Without this field, v2's `links/<key>/` entries silently
    /// shared across peer-divergent installs.
    pub peers: Vec<(String, String)>,
    /// Tarball download URL from registry metadata.
    /// Carried from resolution → download to avoid re-fetching metadata.
    pub tarball_url: Option<String>,
    /// SRI integrity hash (e.g. "sha512-...") from registry metadata.
    pub integrity: Option<String>,
    /// Platform restrictions declared by the selected package version.
    pub platform: Option<PlatformMeta>,
    /// `engines.node` constraint declared by the selected package version.
    pub node_engine: Option<String>,
    /// True when this package is reachable only through optional dependency
    /// edges. Install-time platform filtering skips incompatible optional
    /// packages while failing required ones.
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootResolution {
    pub package: String,
    pub version: String,
}

/// Concrete package selected by the greedy-fusion resolver before the final
/// resolved graph is materialized.
#[derive(Debug, Clone)]
pub struct SelectedPackageEvent {
    pub name: String,
    pub version: String,
    pub is_lpm: bool,
    pub tarball_url: Option<String>,
    pub integrity: Option<String>,
    pub platform: Option<PlatformMeta>,
    pub node_engine: Option<String>,
    pub optional: bool,
}

/// Internal type for PubGrub result + provider (to extract cache).
pub(super) type PubGrubResult = Result<
    (
        pubgrub::SelectedDependencies<LpmDependencyProvider>,
        LpmDependencyProvider,
    ),
    Box<(
        pubgrub::PubGrubError<LpmDependencyProvider>,
        LpmDependencyProvider,
    )>,
>;

/// Result of dependency resolution: resolved packages + metadata cache
/// + override apply trace.
///
/// The cache is returned so callers can run post-resolution checks
/// (e.g., `check_unmet_peers`) against the actual resolved tree. The
/// `applied_overrides` vec is the override apply trace — every override
/// the resolver honored, in `(package, raw_key)` order.
pub struct ResolveResult {
    /// Resolved packages with dependency edges.
    pub packages: Vec<ResolvedPackage>,
    /// Metadata cache from resolution. Contains peer_deps, platform info, etc.
    /// Used by `check_unmet_peers()` for post-resolution peer checking.
    ///
    /// Values are `Arc<CachedPackageInfo>` so the resolver's
    /// end-of-resolve materialization is an `Arc::clone` per entry
    /// (refcount bump) rather than a deep-clone of seven nested
    /// HashMaps. Consumers that need an owned `CachedPackageInfo` can
    /// `(*arc).clone()` at their use site; everything in the codebase
    /// today reads fields through `&Arc<CachedPackageInfo>` (auto-deref).
    pub cache: HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    /// Override apply trace. Empty when no
    /// `lpm.overrides` / `overrides` / `resolutions` were declared OR
    /// when none of them matched any resolved package. Sorted by
    /// `(package, raw_key)` for deterministic output.
    pub applied_overrides: Vec<OverrideHit>,
    /// Count of optional deps skipped because no platform-compatible
    /// version satisfies the declared range on the current OS/CPU.
    /// Surfaced in install `--json` output as
    /// `timing.resolve.platform_skipped` for observability. Taken from
    /// the FINAL successful pass — retry passes share the same fixture
    /// so the count is deterministic.
    pub platform_skipped: usize,
    /// Root-level npm-alias edges the resolver saw on
    /// the consumer's `package.json` deps. Shape:
    /// `local_name → target_canonical_name`. Empty when no root dep
    /// uses `npm:<target>@<range>` syntax. The install pipeline uses
    /// this to (a) drive root `node_modules/<local>/` symlinks and (b)
    /// persist aliases in the lockfile for deterministic re-install.
    pub root_aliases: HashMap<String, String>,
    /// Exact package identities selected for root dependency slots.
    /// Keyed by the local manifest name so npm aliases retain their
    /// project-side link name.
    pub root_resolutions: HashMap<String, RootResolution>,
    /// Ambient installs synthesized by the eager peer-drain pass.
    /// Shape: each entry is the canonical name of a package the
    /// resolver auto-installed because some consumer declared it as a
    /// required peer that wasn't otherwise in the resolved tree.
    /// Sorted alphabetically for deterministic output.
    ///
    /// Why this exists as a separate field: the install pipeline's
    /// `resolved_to_install_packages` derives "is this a top-level
    /// node_modules entry?" from `pkg.dependencies` (the user's
    /// `package.json`). An ambient peer install is NOT in
    /// `package.json` — it was synthesized at resolve-time — so
    /// without this field the install pipeline would extract the
    /// package into the store but never surface it at
    /// `node_modules/<name>/`. Install-side merges this set with
    /// `pkg.dependencies` when computing top-level link names +
    /// direct-dep flags.
    ///
    /// Empty when no peers needed synthesis OR when
    /// `auto_install_peers` was false.
    pub ambient_peer_installs: Vec<String>,
    /// Best-effort peer-conflict reports. Each entry is one peer
    /// canonical whose required consumer ranges were pairwise-
    /// incompatible: lpm picked the version satisfying the most
    /// consumers and recorded the unsatisfied ones here. Mirrors npm
    /// v7+ / pnpm hoisted-mode behavior — pick one peer top-level,
    /// warn the rest. The install pipeline prints a single warning
    /// block per entry after the install summary.
    ///
    /// Sorted alphabetically by `canonical` for deterministic warning
    /// order. Empty when the resolved peer graph is clean.
    pub peer_conflicts: Vec<crate::greedy::PeerConflictReport>,
    /// Substage breakdown of cold-resolve wall-clock.
    /// Observability-only; the fields and their overlap contract are
    /// documented on [`StageTiming`].
    pub stage_timing: StageTiming,
}

/// Peer fixed-point amplification and timing for one resolver pass.
#[derive(Debug, Clone, Default, Copy)]
pub struct PeerStageTiming {
    /// Non-empty peer worklist passes executed by the fixed-point resolver.
    pub non_empty_pass_count: u64,
    /// Peer requirements visited across all non-empty passes.
    pub requirement_count: u64,
    /// Distinct `(consumer node, peer local name)` requirements visited.
    pub unique_requirement_count: u64,
    /// Canonical peer groups considered across all passes.
    pub group_count: u64,
    /// Groups satisfied entirely by versions already selected in the graph.
    pub already_satisfied_group_count: u64,
    /// Groups that reached peer policy and version classification.
    pub classified_group_count: u64,
    /// Classified groups skipped because they were optional-only or peer
    /// auto-install was disabled.
    pub skipped_opt_out_group_count: u64,
    /// Reused peer decisions for an identical canonical and consumer context.
    pub resolution_cache_hit_count: u64,
    /// Peer decisions computed for a new canonical and consumer context.
    pub resolution_cache_miss_count: u64,
    /// Manifest lookups awaited by peer processing, including cache-backed
    /// policy hydration.
    pub manifest_lookup_count: u64,
    /// Wall-clock nanoseconds spent awaiting peer manifest lookups.
    pub manifest_wait_ns: u64,
    /// Peer-drain wall-clock nanoseconds excluding measured manifest waits.
    pub processing_ns: u64,
    /// Ambient root-scoped edges synthesized by peer processing.
    pub synthesized_edge_count: u64,
}

/// Per-substage wall-clock breakdown emitted by
/// [`resolve_with_shared_cache`].
///
/// Scope: the counters are reset at the start of every
/// `resolve_with_shared_cache` call and snapshot at the end, so they
/// capture work done by the RESOLVER — not install.rs's walker
/// roots-ready wait. install.rs measures that separately
/// (`timing.resolve.initial_batch_ms`) and combines both numbers
/// before surfacing to `--json`.
///
/// Field contract:
/// - `followup_rpc_ms` + `followup_rpc_count` are the follow-up
///   metadata fetches fired from inside the provider's callbacks
///   (follow-up depth/fanout lever). On a fully-cached warm install
///   they're both zero; on a cold install with a shallow worker
///   deep-walk they dominate `resolve_ms`.
/// - `parse_ndjson_ms` is serde_json CPU time for follow-up batches
///   only. The initial batch's parse time is folded into
///   install.rs's `initial_batch_ms` wall-clock.
/// - `pubgrub_ms` covers every pass of the `spawn_blocking` that
///   runs `pubgrub::resolve()` — sum across split-retry passes. Includes
///   any provider callback time, so `pubgrub_ms - followup_rpc_ms`
///   approximates pubgrub-core work (backtracking, selection).
#[derive(Debug, Clone, Default, Copy)]
pub struct StageTiming {
    /// Wall-clock spent in follow-up metadata RPCs triggered from
    /// inside the resolver's PubGrub callbacks. Does NOT include
    /// install.rs's pre-resolve initial batch. Reset + snapshot
    /// boundaries ensure this number is zero when the resolver is
    /// called on a warm cache with no cache misses.
    pub followup_rpc_ms: u64,
    /// Total number of metadata RPCs that went to the network during
    /// this resolve pass. Equals
    /// `walker_rpc_count + escape_hatch_rpc_count`. Previously this
    /// field conflated walker fetches and provider escape-hatch
    /// fetches; now the two are reported separately on
    /// `walker_rpc_count` / `escape_hatch_rpc_count` below. This
    /// total stays for backward compatibility with `--json` consumers.
    pub followup_rpc_count: u32,
    /// NDJSON deserialization CPU time for follow-up batches. Grows
    /// with the total number of VERSIONS across those batches, so
    /// it's a direct signal for whether slimmer batch responses would
    /// help. Initial batch parse time is folded into
    /// `initial_batch_ms` on the install side.
    pub parse_ndjson_ms: u64,
    /// Wall-clock spent inside the `spawn_blocking` that hosts
    /// `pubgrub::resolve()`. Summed across split-retry passes. On
    /// the happy path (no retries) this equals the resolver's
    /// total work.
    pub pubgrub_ms: u64,
    /// Number of metadata RPCs the walker fired. Each parallel-fetch
    /// per-package GET counts once; each `batch_metadata` call counts
    /// once regardless of name count. High walker_rpc + low
    /// escape_hatch = walker working well. Low walker_rpc + high
    /// escape_hatch = walker depth/fanout undersized.
    ///
    /// Zero under the fused dispatcher (`LPM_GREEDY_FUSION=1`) since
    /// the walker is bypassed entirely. Use `dispatcher_rpc_count`
    /// instead for the fusion arm.
    pub walker_rpc_count: u32,
    /// Number of metadata RPCs the provider's escape hatch fired
    /// (manifests not produced by the walker before
    /// `fetch_wait_timeout` expired). The actionable signal — see
    /// `walker_rpc_count` for tuning levers.
    ///
    /// Zero under the fused dispatcher — there is no escape-hatch
    /// path because there is no walker to be missed.
    pub escape_hatch_rpc_count: u32,
    /// Total metadata RPCs the fused dispatcher fired
    /// during this resolve pass. Replaces
    /// `walker_rpc_count + escape_hatch_rpc_count` under fusion: each
    /// per-canonical fetch counts once whether driven by a root edge
    /// or a transitive child completion. Zero on the walker arm.
    /// Equality `dispatcher_rpc_count == walker_rpc_count +
    /// escape_hatch_rpc_count` (modulo arm) is a sanity check on the
    /// instrumentation.
    pub dispatcher_rpc_count: u64,
    /// Configured permit count for direct metadata fetches in the fused
    /// dispatcher. Zero on resolver arms that do not use this semaphore.
    pub dispatcher_configured_fanout: u64,
    /// Peak number of direct metadata fetches holding semaphore permits.
    /// This value cannot exceed [`Self::dispatcher_configured_fanout`].
    pub dispatcher_inflight_high_water: u64,
    /// Peak number of canonical metadata requests pending in the resolver
    /// dispatcher, including direct jobs waiting for permits and Worker root
    /// or tail batch candidates.
    pub dispatcher_pending_high_water: u64,
    /// Number of direct metadata jobs that had to wait for a semaphore permit.
    pub dispatcher_semaphore_wait_count: u64,
    /// Total direct metadata semaphore wait time in nanoseconds.
    pub dispatcher_semaphore_wait_ns: u64,
    /// `max(parked.values().map(|v| v.len()))` over the
    /// life of the fused dispatcher loop. Catches pathological
    /// parking — e.g., every edge in the tree blocked on one slow
    /// canonical's manifest. Healthy values are O(distinct version
    /// requests for the same canonical from sibling parents); any
    /// reading in the hundreds is a signal the registry is stalling
    /// on one specific package.
    pub parked_max_depth: u32,
    /// Count of selected-version metadata frames emitted to an optional
    /// install-side tarball speculation channel. Zero on the walker arm
    /// and on fusion callers that do not pass a speculation channel.
    pub tarball_dispatched_count: u64,
    /// Count of speculative peer-manifest fetches the fused dispatcher
    /// dispatched concurrent with the regular dep walk. Each prefetch
    /// corresponds to one `peerDependencies` requirement that (at the
    /// moment the queue-drain step completed) was: non-optional, not yet satisfied
    /// by the resolved tree, not yet in the shared cache, and not yet
    /// in flight from a sibling dispatch.
    ///
    /// **What this counter means observability-wise:**
    /// - `0` — no required peers were missing at any point during the
    ///   resolve, OR `auto_install_peers` was off.
    /// - `> 0` — peer fetches that would have run SERIALLY in the
    ///   post-loop drain pass instead ran concurrently with the
    ///   regular dep dispatch. Each prefetch saves one network
    ///   round-trip from the critical path.
    /// - The counter MAY be lower than `len(ambient_peer_installs)`:
    ///   a peer canonical that gets pulled in as a regular transitive
    ///   AFTER the prefetch dispatched is still counted; but a peer
    ///   canonical pulled in BEFORE the prefetch evaluated (cache hit
    ///   at picker time) will NOT bump this counter. The counter
    ///   measures "prefetches we issued," not "peers that ultimately
    ///   landed."
    ///
    /// Zero on the walker arm (speculative prefetch is fused-only —
    /// the walker arm is the legacy opt-out and not a performance
    /// target).
    pub peer_prefetch_count: u64,
    /// Number of dependency edges processed by the greedy resolver.
    pub work_edge_process_count: u64,
    /// Edges that reused an existing selected node rather than allocating
    /// a new `(canonical, version)` node.
    pub work_edge_reuse_count: u64,
    /// Legacy range-compatible reuse count. Exact selected-identity
    /// resolution leaves this at zero.
    pub work_edge_reuse_range_count: u64,
    /// Reuse count where the edge's selected package identity matched an
    /// existing node exactly.
    pub work_edge_reuse_exact_count: u64,
    /// Number of selected nodes allocated by the greedy resolver.
    pub work_node_allocated_count: u64,
    /// Regular dependency edges enqueued from selected package manifests.
    pub work_child_edge_enqueued_count: u64,
    /// Peer requirements collected from selected package manifests.
    pub work_peer_requirement_count: u64,
    /// Peer fixed-point amplification and processing breakdown.
    pub peer: PeerStageTiming,
    /// Distinct canonical metadata misses from dependency edges in the greedy
    /// task queue. Populated only when metadata trace detail is enabled.
    /// Tree-policy lookahead and peer-prefetch fetches are tracked by
    /// dispatcher counters, but do not have a single triggering range for the
    /// edge-shape attribution below.
    pub work_metadata_edge_miss_count: u64,
    /// Task-queue edge metadata misses whose canonical routed directly to npm.
    pub work_metadata_edge_miss_direct_count: u64,
    /// Task-queue edge metadata misses whose fetched metadata exposed a
    /// parseable `latest` dist-tag.
    pub work_metadata_edge_miss_latest_known_count: u64,
    /// Direct-npm task-queue edge metadata misses whose fetched metadata
    /// exposed a parseable `latest` dist-tag.
    pub work_metadata_edge_miss_latest_known_direct_count: u64,
    /// Task-queue edge metadata misses whose triggering range would accept the
    /// fetched `latest` dist-tag.
    pub work_metadata_edge_miss_latest_satisfies_count: u64,
    /// Direct-npm task-queue edge metadata misses whose triggering range would
    /// accept the fetched `latest` dist-tag.
    pub work_metadata_edge_miss_latest_satisfies_direct_count: u64,
    /// Task-queue edge metadata misses where the fetched `latest` dist-tag
    /// equals the policy-aware version pick from the full metadata.
    pub work_metadata_edge_miss_latest_matches_pick_count: u64,
    /// Direct-npm task-queue edge metadata misses where the fetched `latest`
    /// dist-tag equals the policy-aware version pick from the full metadata.
    pub work_metadata_edge_miss_latest_matches_pick_direct_count: u64,
    /// Task-queue edge metadata misses where a single-version document could
    /// satisfy resolver policy without package-level history.
    pub work_metadata_edge_miss_version_doc_policy_eligible_count: u64,
    /// Direct-npm task-queue edge metadata misses where a single-version
    /// document could satisfy resolver policy without package-level history.
    pub work_metadata_edge_miss_version_doc_policy_eligible_direct_count: u64,
    /// Task-queue edge metadata misses where `latest` matches the full-metadata
    /// pick and a single-version document could satisfy resolver policy.
    pub work_metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_count: u64,
    /// Direct-npm task-queue edge metadata misses where `latest` matches the
    /// full-metadata pick and a single-version document could satisfy resolver
    /// policy.
    pub work_metadata_edge_miss_latest_matches_pick_version_doc_policy_eligible_direct_count: u64,
    /// Task-queue edge metadata misses whose triggering edge used an exact version.
    pub work_metadata_edge_miss_exact_count: u64,
    /// Task-queue edge metadata misses whose triggering edge used `*`, empty,
    /// or `latest`.
    pub work_metadata_edge_miss_star_count: u64,
    /// Task-queue edge metadata misses whose triggering edge used a caret range.
    pub work_metadata_edge_miss_caret_count: u64,
    /// Task-queue edge metadata misses whose triggering edge used a tilde range.
    pub work_metadata_edge_miss_tilde_count: u64,
    /// Task-queue edge metadata misses whose triggering edge used a comparator
    /// range.
    pub work_metadata_edge_miss_comparator_count: u64,
    /// Task-queue edge metadata misses whose triggering edge used a
    /// union/hyphen/compound range.
    pub work_metadata_edge_miss_complex_count: u64,
    /// Task-queue edge metadata misses whose triggering edge used another valid
    /// range shape.
    pub work_metadata_edge_miss_other_count: u64,
    /// Final selected package rows emitted to the install pipeline.
    pub selected_package_count: u64,
    /// Distinct canonical packages in the final selected package rows.
    pub selected_unique_canonical_count: u64,
    /// Extra selected rows caused by multiple versions of the same canonical
    /// package being present in the graph.
    pub selected_duplicate_canonical_count: u64,
    /// CPU time spent evaluating minimum-release-age policy checks.
    /// Counts every candidate check, including cached metadata paths
    /// where no network request was needed.
    pub policy_release_age_ms: u64,
    /// Number of candidate versions evaluated by release-age policy.
    pub policy_release_age_checked_count: u64,
    /// Number of release-age checks that rejected a candidate.
    pub policy_release_age_rejected_count: u64,
    /// Number of release-age rejections caused by missing publish time.
    pub policy_release_age_missing_count: u64,
    /// CPU time spent evaluating trust no-downgrade policy checks.
    pub policy_trust_ms: u64,
    /// Number of candidate versions evaluated by trust policy.
    pub policy_trust_checked_count: u64,
    /// Number of trust-policy checks that rejected a candidate.
    pub policy_trust_rejected_count: u64,
}
