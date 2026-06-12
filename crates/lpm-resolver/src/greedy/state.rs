use super::peer::{CachedPeerResolution, PeerResolutionCacheKey};
use super::prelude::*;
use super::types::{DepBehavior, Edge, NodeId, PeerConflictReport, PeerRequirement};
use super::version::is_workspace_specifier;

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
    /// `Vec<ResolvedPackage>`. Mirrors `resolve.rs::format_solution`.
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
