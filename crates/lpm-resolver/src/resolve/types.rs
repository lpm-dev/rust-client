use super::prelude::*;

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
    /// True when this package is reachable only through optional dependency
    /// edges. Install-time platform filtering skips incompatible optional
    /// packages while failing required ones.
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
///   runs `pubgrub::resolve()` — sum across split-retries. Includes
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
    /// Peak `metadata_jobs.len()` observed between queue-drain and
    /// bounded-await steps of the fused dispatcher loop. Confirms the metadata
    /// semaphore is the binding constraint when this approaches the
    /// configured fanout; if it sits well below, the binding
    /// constraint is something upstream (h2 single-connection flow
    /// control, h1-pool socket count, or a serialization in
    /// `process_edge`).
    pub dispatcher_inflight_high_water: u64,
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
