use super::prelude::*;

/// Internal node identity used while the resolver runs. Maps to a
/// final [`ResolvedPackage`] at the end of the pass. Each unique
/// `(canonical, version)` pair gets its own id; multi-version
/// canonicals (e.g. `is-unicode-supported@1.3.0` + `is-unicode-supported
/// @2.1.0` both alive in the same install) produce two distinct ids.
pub(super) type NodeId = u32;

/// One unresolved edge: parent N needs `name @ range` with `behavior`.
///
/// Carries enough context for [`process_edge`] to look up the right
/// manifest, pick a version, and link parent → child in the resolved tree.
#[derive(Debug, Clone)]
pub(super) struct Edge {
    /// Parent node in the resolved tree. The root project is the
    /// only node without a parent — it's seeded explicitly before
    /// the loop starts.
    pub(super) parent: NodeId,
    /// Local name in the parent's `dependencies` map (alias-aware).
    /// When this differs from `canonical`, the edge was declared via
    /// `npm:<target>@<range>` and `local_name → target` is recorded on
    /// the parent's resolved node so the linker can build
    /// `node_modules/<local>/` → store entry for `<target>`.
    pub(super) local_name: String,
    /// Canonical (registry-side) name of the dependency. Equal to
    /// `local_name` for non-aliased edges; equal to the alias target
    /// for aliased edges.
    pub(super) canonical: CanonicalKey,
    /// Semver range to satisfy.
    pub(super) range: NpmRange,
    /// What kind of dep this is — affects error semantics on miss.
    pub(super) behavior: DepBehavior,
}

/// A single `peerDependencies[name]` declaration captured during the walk.
///
/// Distinct shape from [`Edge`]: peer requirements are NOT enqueued
/// on the dispatcher's `task_queue`. Peers are treated as a separate
/// input class so they map to `ResolvedPackage.peers` rather than
/// `ResolvedPackage.dependencies`. The v2 store's graph-key derivation
/// depends on this separation; silently routing peers through `n.children`
/// would break peer-divergent link-entry isolation.
// Fields are read by peer-collection tests below + the peer-drain pass. `#[allow(dead_code)]`
// at the struct level rather than per-field keeps the doc readable —
// the struct doc explains the future-use contract.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(super) struct PeerRequirement {
    /// The package that DECLARED this peer dep — i.e. the consumer
    /// of the peer. Stored as a [`NodeId`] (already-allocated node)
    /// because peer collection happens at child-deps-enqueue time,
    /// when the consumer node is known.
    pub(super) consumer: NodeId,
    /// Local name of the peer as it appears in `peerDependencies`.
    /// May differ from [`Self::canonical`] only in the (rare) case
    /// where an `npm:<target>@<range>` alias is also declared on the
    /// peer key — npm permits this and the canonical is then the
    /// alias target.
    pub(super) peer_name: String,
    /// Registry identity (alias-aware).
    pub(super) canonical: CanonicalKey,
    /// Parsed range from the `peerDependencies` value.
    pub(super) range: NpmRange,
    /// `peerDependenciesMeta.<name>.optional` flag for this peer.
    /// The peer-drain step skips optional peers when synthesizing
    /// ambient installs (the manifest author opted out); the
    /// post-resolve `check_unmet_peers` pass already suppresses the
    /// missing-peer warning for this set.
    pub(super) optional: bool,
}

/// One best-effort peer-conflict report. Surfaced when a peer canonical
/// has multiple required consumers whose ranges are pairwise-incompatible —
/// lpm picks the version that satisfies the most consumers and records the
/// unsatisfied ones here for the install pipeline to warn about. Mirrors
/// npm v7+'s "pick one + warn the rest" behavior on hoisted layouts.
#[derive(Debug, Clone)]
pub struct PeerConflictReport {
    /// Peer canonical name (e.g., `"react"` or `"@scope/foo"`).
    pub canonical: String,
    /// Version lpm chose to ambient-install at top level. Satisfies at
    /// least one required consumer's range (if zero consumers were
    /// satisfiable, the resolver hard-errors with `PeerConflict`
    /// instead of producing this report).
    pub chosen_version: String,
    /// `(consumer_canonical, declared_range)` for required consumers
    /// whose range does NOT include `chosen_version`. Stable order:
    /// matches the order the requirements were registered in.
    pub unsatisfied_consumers: Vec<(String, String)>,
}

/// Dependency behavior flags for resolver miss semantics.
///
/// Root-level dev dependencies are treated as required (only root
/// edges are ever marked dev — transitive `devDependencies` are not
/// followed by npm clients per spec). The `required` bit is retained
/// for the point where peer and required miss semantics diverge.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct DepBehavior {
    #[allow(dead_code)] // retained for peer/required miss semantics once they diverge
    pub(super) required: bool,
    pub(super) peer: bool,
    pub(super) optional: bool,
}

/// Per-canonical manifest state.
#[allow(dead_code)]
pub(super) type ManifestState = Arc<CachedPackageInfo>;
