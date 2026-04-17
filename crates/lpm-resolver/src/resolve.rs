//! High-level resolution entry point.
//!
//! Iterative split-retry approach:
//! 1. Try flat resolution (one version per package) — works for ~90% of real trees
//! 2. On conflict, identify packages needing multiple versions and retry with splits
//! 3. Keep adding new split candidates until resolution succeeds or no new candidates remain

use crate::npm_version::NpmVersion;
use crate::overrides::{OverrideHit, OverrideSet};
use crate::package::ResolverPackage;
use crate::provider::{CachedPackageInfo, LpmDependencyProvider};
use lpm_registry::RegistryClient;
use pubgrub::{DefaultStringReporter, Reporter};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::runtime::Handle;

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
    /// Phase 40 P2 npm-alias deps (e.g., `"strip-ansi-cjs": "npm:strip-ansi@^6"`)
    /// it is the alias key, and the `aliases` map below records the
    /// alias's canonical target name. Keeping the local name as the
    /// edge key means the linker can build `node_modules/<local>/`
    /// directly from the edge without a second lookup.
    pub dependencies: Vec<(String, String)>,
    /// **Phase 40 P2** — npm-alias edges. Key = `dep_name_in_parent`
    /// from the `dependencies` vec; value = target canonical package
    /// name (what to fetch from the registry + how the `.lpm/` store
    /// entry is keyed). Empty for packages that declare no aliased
    /// deps (the common case). Non-aliased edges are NOT present —
    /// callers compute `aliases.get(local).unwrap_or(local)` to get
    /// the target.
    pub aliases: HashMap<String, String>,
    /// Tarball download URL from registry metadata.
    /// Carried from resolution → download to avoid re-fetching metadata.
    pub tarball_url: Option<String>,
    /// SRI integrity hash (e.g. "sha512-...") from registry metadata.
    pub integrity: Option<String>,
}

/// Internal type for PubGrub result + provider (to extract cache).
type PubGrubResult = Result<
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
/// `applied_overrides` vec is the Phase 32 Phase 5 apply trace — every
/// override the resolver honored, in `(package, raw_key)` order.
pub struct ResolveResult {
    /// Resolved packages with dependency edges.
    pub packages: Vec<ResolvedPackage>,
    /// Metadata cache from resolution. Contains peer_deps, platform info, etc.
    /// Used by `check_unmet_peers()` for post-resolution peer checking.
    pub cache: HashMap<ResolverPackage, CachedPackageInfo>,
    /// **Phase 32 Phase 5** — override apply trace. Empty when no
    /// `lpm.overrides` / `overrides` / `resolutions` were declared OR
    /// when none of them matched any resolved package. Sorted by
    /// `(package, raw_key)` for deterministic output.
    pub applied_overrides: Vec<OverrideHit>,
    /// **Phase 40 P1** — count of optional deps skipped because no
    /// platform-compatible version satisfies the declared range on the
    /// current OS/CPU. Surfaced in install `--json` output as
    /// `timing.resolve.platform_skipped` for observability (matches the
    /// platform-skip shape bun reports via `--dry-run`). Taken from the
    /// FINAL successful pass — retry passes share the same fixture so
    /// the count is deterministic.
    pub platform_skipped: usize,
    /// **Phase 40 P2** — root-level npm-alias edges the resolver saw on
    /// the consumer's `package.json` deps. Shape:
    /// `local_name → target_canonical_name`. Empty when no root dep
    /// uses `npm:<target>@<range>` syntax. The install pipeline uses
    /// this to (a) drive root `node_modules/<local>/` symlinks and (b)
    /// persist aliases in the lockfile for deterministic re-install.
    pub root_aliases: HashMap<String, String>,
    /// **Phase 40 P3a** — substage breakdown of cold-resolve wall-clock.
    /// Observability-only; the fields and their overlap contract are
    /// documented on [`StageTiming`].
    pub stage_timing: StageTiming,
}

/// Per-substage wall-clock breakdown emitted by
/// [`resolve_with_prefetch`].
///
/// Scope: the counters are reset at the start of every
/// `resolve_with_prefetch` call and snapshot at the end, so they
/// capture work done by the RESOLVER — not install.rs's
/// pre-resolution initial batch. install.rs measures that
/// separately and combines both numbers before surfacing to
/// `--json`.
///
/// Field contract:
/// - `followup_rpc_ms` + `followup_rpc_count` are the follow-up
///   metadata fetches fired from inside the provider's callbacks
///   (the Phase 40 P3b/P3c lever). On a fully-cached warm install
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
    /// Number of follow-up metadata RPCs that went to the network.
    /// TTL cache hits and 304 revalidations do NOT contribute. A
    /// number in the low tens means the worker's deep-walk covered
    /// the tree well; hundreds means the P3b lever (bump deep-walk
    /// depth) is the right next move.
    pub followup_rpc_count: u32,
    /// NDJSON deserialization CPU time for follow-up batches. Grows
    /// with the total number of VERSIONS across those batches, so
    /// it's a direct signal for the P3d "slim the batch response"
    /// lever. Initial batch parse time is folded into
    /// `initial_batch_ms` on the install side.
    pub parse_ndjson_ms: u64,
    /// Wall-clock spent inside the `spawn_blocking` that hosts
    /// `pubgrub::resolve()`. Summed across split-retry passes. On
    /// the happy path (no retries) this equals the resolver's
    /// total work.
    pub pubgrub_ms: u64,
}

/// Resolve dependencies for a project.
///
/// Uses an iterative split-retry approach:
/// 1. Start with flat resolution using PubGrub (one version per package)
/// 2. On each `NoSolution`, extract conflicting packages and add them to the split set
/// 3. Retry until resolution succeeds or the conflict report yields no new split candidates
///
/// Returns resolved packages with their dependency edges populated from
/// the resolver's metadata cache.
pub async fn resolve_dependencies(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
) -> Result<ResolveResult, ResolveError> {
    resolve_dependencies_with_overrides(client, dependencies, OverrideSet::empty()).await
}

/// Resolve with the Phase 32 Phase 5 fully-parsed [`OverrideSet`].
///
/// **Path-selector wiring.** If the override set declares any path
/// selectors, the canonical names of their targets are added to the
/// resolver's split set BEFORE Phase 1 runs. This guarantees that path
/// selectors work in flat resolution — the resolver doesn't have to
/// fall through to split-on-conflict retries for an override to take
/// effect. Every retry inherits the same set so conflict-driven splits
/// union with the override-driven ones.
pub async fn resolve_dependencies_with_overrides(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
) -> Result<ResolveResult, ResolveError> {
    resolve_with_prefetch(client, dependencies, overrides, None).await
}

/// Phase 34.5: resolve with optional pre-fetched batch metadata.
///
/// When `prefetched` is `Some`, the batch metadata from `install.rs` is
/// passed directly into the provider's in-memory cache, avoiding disk
/// reads during resolution. This eliminates the dominant warm-resolve
/// cost (~24ms of ~25ms) by skipping HMAC verification + MessagePack
/// deserialization for every package.
pub async fn resolve_with_prefetch(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: OverrideSet,
    prefetched: Option<HashMap<String, lpm_registry::PackageMetadata>>,
) -> Result<ResolveResult, ResolveError> {
    let _span = tracing::debug_span!("resolve", n_deps = dependencies.len()).entered();
    let rt = Handle::current();

    // Phase 34.4: reset profiling accumulators once before resolution starts.
    // Counters accumulate across all retry passes so the final summary
    // reflects the total resolver work, not just the last pass.
    crate::profile::reset_all();

    // Phase 40 P3a — reset the registry-side metadata/parse
    // accumulators so `snapshot()` at the end of this call reports
    // only work done since entry. Safe to call even when the caller
    // already warmed the metadata cache via install.rs's initial
    // batch — THAT phase's contribution is captured separately by
    // the install-side timer.
    lpm_registry::timing::reset();

    // Pre-compute the split set from path selectors. Empty when no
    // path-selector overrides are declared, which keeps the no-overrides
    // path on the existing zero-allocation hot loop.
    let mut split_packages: HashSet<String> = overrides.split_targets().clone();
    let mut cached_metadata: Option<HashMap<ResolverPackage, CachedPackageInfo>> = None;
    let mut prefetched = prefetched;
    let mut attempt = 0usize;

    // Phase 40 P3a — accumulate pubgrub wall-clock across split-retry
    // passes. The `spawn_blocking` hosting `pubgrub::resolve()` is
    // the innermost correct boundary; anything outside (queueing,
    // Tokio task switching) is background noise that shouldn't
    // dominate on cold installs but could mislead the P3 breakdown
    // if lumped in.
    let mut pubgrub_ms_total: u128 = 0;

    let final_result = loop {
        let deps_for_pass = dependencies.clone();
        let client_for_pass = client.clone();
        let rt_for_pass = rt.clone();
        let overrides_for_pass = overrides.clone();
        let split_packages_for_pass = split_packages.clone();
        let cache_for_pass = cached_metadata.take();
        let prefetched_for_pass = prefetched.take();

        let pass_start = std::time::Instant::now();
        let result: PubGrubResult = tokio::task::spawn_blocking(move || {
            let mut provider = if split_packages_for_pass.is_empty() {
                LpmDependencyProvider::new(client_for_pass, rt_for_pass, deps_for_pass)
            } else {
                LpmDependencyProvider::new_with_splits(
                    client_for_pass,
                    rt_for_pass,
                    deps_for_pass,
                    split_packages_for_pass,
                )
            }
            .with_overrides(overrides_for_pass);

            if let Some(cache) = cache_for_pass {
                provider = provider.with_cache(cache);
            }

            // Phase 34.5: pre-seed in-memory cache from batch prefetch results.
            // Only needed on the first pass; later retries reuse the carried cache.
            if let Some(batch) = prefetched_for_pass {
                provider = provider.with_prefetched_metadata(&batch);
            }

            match pubgrub::resolve(&provider, ResolverPackage::Root, NpmVersion::new(0, 0, 0)) {
                Ok(solution) => Ok((solution, provider)),
                Err(e) => Err(Box::new((e, provider))),
            }
        })
        .await
        .map_err(|e| ResolveError::Internal(format!("resolver task panicked: {e}")))?;
        // Phase 40 P3a — accumulate this pass's pubgrub wall-clock.
        // Split-retry passes each add to the total, matching how
        // `metadata_rpc_ms` accumulates at the registry layer.
        pubgrub_ms_total = pubgrub_ms_total.saturating_add(pass_start.elapsed().as_millis());

        match result {
            Ok((solution, provider)) => {
                let (cache, applied_overrides, platform_skipped, root_aliases) =
                    provider.into_parts();
                let packages = format_solution(solution, &cache);
                // Phase 40 P3a — snapshot substage counters at the
                // tail of the happy path. The registry-side atomics
                // were reset at the top of this call, so they now
                // reflect only follow-up RPCs (the initial batch
                // landed BEFORE `resolve_with_prefetch` was called
                // and is tracked separately by install.rs).
                let snap = lpm_registry::timing::snapshot();
                let stage_timing = StageTiming {
                    followup_rpc_ms: snap.metadata_rpc.as_millis() as u64,
                    followup_rpc_count: snap.metadata_rpc_count,
                    parse_ndjson_ms: snap.parse_ndjson.as_millis() as u64,
                    pubgrub_ms: pubgrub_ms_total as u64,
                };
                break Ok(ResolveResult {
                    packages,
                    cache,
                    applied_overrides,
                    platform_skipped,
                    root_aliases,
                    stage_timing,
                });
            }
            Err(err) if matches!(err.0, pubgrub::PubGrubError::NoSolution(_)) => {
                let (pubgrub::PubGrubError::NoSolution(mut derivation_tree), provider) = *err
                else {
                    unreachable!()
                };
                derivation_tree.collapse_no_versions();
                let report = DefaultStringReporter::report(&derivation_tree);

                let conflicting = extract_conflicting_packages(&report);
                if conflicting.is_empty() {
                    break Err(ResolveError::NoSolution(report));
                }

                let mut new_splits: Vec<String> = conflicting
                    .into_iter()
                    .filter(|pkg| !split_packages.contains(pkg))
                    .collect();
                if new_splits.is_empty() {
                    break Err(ResolveError::NoSolution(report));
                }

                new_splits.sort();
                split_packages.extend(new_splits.iter().cloned());
                cached_metadata = Some(provider.into_cache());
                attempt += 1;

                if attempt == 1 {
                    tracing::info!(
                        "flat resolution failed, splitting {} package(s): {}",
                        split_packages.len(),
                        split_packages
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                } else {
                    tracing::info!(
                        "split pass {} failed, adding {} more split package(s): {}",
                        attempt,
                        new_splits.len(),
                        new_splits.join(", ")
                    );
                }
            }
            Err(err) => break Err(map_pubgrub_error(err.0)),
        }
    };

    // Phase 34.4: dump cumulative resolver profile AFTER all passes complete.
    // Counters accumulate across all split-retry passes.
    tracing::debug!(
        "resolver profile (all passes):\n{}",
        crate::profile::summary()
    );

    final_result
}

/// Convert PubGrub solution + cached metadata into `ResolvedPackage` list
/// with dependency edges populated.
fn format_solution(
    solution: pubgrub::SelectedDependencies<LpmDependencyProvider>,
    cache: &HashMap<ResolverPackage, CachedPackageInfo>,
) -> Vec<ResolvedPackage> {
    // Build a lookup: canonical_name → resolved_version for cross-referencing deps
    let resolved_versions: HashMap<String, String> = solution
        .iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(pkg, ver)| (pkg.canonical_name(), ver.to_string()))
        .collect();

    let mut resolved: Vec<ResolvedPackage> = solution
        .into_iter()
        .filter(|(pkg, _)| !pkg.is_root())
        .map(|(package, version)| {
            let ver_str = version.to_string();

            // Phase 40 P2 — pull the per-version alias map from the
            // cache so we can (a) redirect edge-lookup to the aliased
            // target's resolved version and (b) surface the alias map
            // on the resolved package for the linker.
            let cached_aliases: HashMap<String, String> = cache
                .get(&package)
                .and_then(|info| info.aliases.get(&ver_str))
                .cloned()
                .unwrap_or_default();

            // Look up this package's declared deps from the provider
            // cache. `ver_deps` is keyed by the LOCAL dep name (what
            // appears in the parent's `dependencies` map). To look up
            // the resolved version in `resolved_versions` (keyed by
            // the child's canonical registry name) we redirect through
            // the per-version alias map.
            let dependencies = cache
                .get(&package)
                .and_then(|info| info.deps.get(&ver_str))
                .map(|ver_deps| {
                    ver_deps
                        .keys()
                        .filter_map(|local_name| {
                            let target_name = cached_aliases
                                .get(local_name)
                                .map(String::as_str)
                                .unwrap_or(local_name.as_str());
                            resolved_versions
                                .get(target_name)
                                .map(|resolved_ver| (local_name.clone(), resolved_ver.clone()))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            // Only surface aliases that actually survived resolution —
            // an optional aliased dep skipped by the platform filter is
            // not in `dependencies`, so carrying its alias entry would
            // be dead weight for the linker.
            let alive_locals: HashSet<&String> = dependencies.iter().map(|(l, _)| l).collect();
            let aliases: HashMap<String, String> = cached_aliases
                .iter()
                .filter(|(local, _)| alive_locals.contains(local))
                .map(|(l, t)| (l.clone(), t.clone()))
                .collect();

            // Extract tarball URL and integrity from cached dist info
            let (tarball_url, integrity) = cache
                .get(&package)
                .and_then(|info| info.dist.get(&ver_str))
                .map(|d| (d.tarball_url.clone(), d.integrity.clone()))
                .unwrap_or_default();

            ResolvedPackage {
                package,
                version,
                dependencies,
                aliases,
                tarball_url,
                integrity,
            }
        })
        .collect();
    resolved.sort_by(|a, b| a.package.to_string().cmp(&b.package.to_string()));
    resolved
}

/// A warning about an unmet peer dependency.
///
/// Peer deps are checked post-resolution against the actual resolved tree,
/// not during resolution. This avoids over-constraining (union-across-all-versions)
/// and matches npm/pnpm behavior.
#[derive(Debug, Clone)]
pub struct PeerWarning {
    /// The package that declares the peer dependency.
    pub package: String,
    /// The version of the package that declares the peer.
    pub version: String,
    /// The peer dependency name.
    pub peer: String,
    /// The required peer version range.
    pub required_range: String,
    /// The version actually resolved in the tree (None if peer is completely missing).
    pub resolved_version: Option<String>,
}

impl std::fmt::Display for PeerWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.resolved_version {
            Some(v) => write!(
                f,
                "{}@{} requires peer {} ({}), but {}@{} was resolved",
                self.package, self.version, self.peer, self.required_range, self.peer, v
            ),
            None => write!(
                f,
                "{}@{} requires peer {} ({}), but it is not installed",
                self.package, self.version, self.peer, self.required_range
            ),
        }
    }
}

/// Check the resolved tree for unmet peer dependencies.
///
/// For each resolved package, looks up its *actual selected version's* peer deps
/// from the cached metadata, then checks whether the resolved tree satisfies them.
///
/// Returns a list of warnings for unmet peers. This is intentionally warnings-only
/// (not errors) to match npm's default peer behavior. Strict mode enforcement
/// is the caller's responsibility.
pub fn check_unmet_peers(
    resolved: &[ResolvedPackage],
    cache: &HashMap<ResolverPackage, CachedPackageInfo>,
) -> Vec<PeerWarning> {
    use crate::ranges::NpmRange;

    // Build lookup: canonical_name → all resolved instances for that package.
    // Split packages may legitimately appear multiple times with different contexts.
    let resolved_versions: HashMap<String, Vec<(Option<String>, String)>> =
        resolved.iter().fold(HashMap::new(), |mut acc, package| {
            acc.entry(package.package.canonical_name())
                .or_default()
                .push((
                    package.package.context().map(str::to_string),
                    package.version.to_string(),
                ));
            acc
        });

    // Build fast lookup for unsplit peers that can be shared globally.
    let unsplit_versions: HashMap<String, String> = resolved
        .iter()
        .filter(|package| package.package.context().is_none())
        .map(|package| {
            (
                package.package.canonical_name(),
                package.version.to_string(),
            )
        })
        .collect();

    let mut warnings = Vec::new();

    for resolved_pkg in resolved {
        let ver_str = resolved_pkg.version.to_string();
        let canonical = resolved_pkg.package.canonical_name();

        // Look up this package's peer deps for its actual resolved version
        let peer_deps = cache
            .get(&resolved_pkg.package)
            .and_then(|info| info.peer_deps.get(&ver_str));

        let Some(peer_deps) = peer_deps else {
            continue;
        };

        for (peer_name, peer_range_str) in peer_deps {
            let resolved_peer_ver = resolve_peer_version(
                &resolved_pkg.package,
                peer_name,
                &resolved_versions,
                &unsplit_versions,
            );

            match resolved_peer_ver {
                Some(resolved_ver) => {
                    // Peer is in the tree — check if the resolved version satisfies the range
                    let satisfies = NpmRange::parse(peer_range_str)
                        .ok()
                        .and_then(|range| {
                            NpmVersion::parse(resolved_ver)
                                .ok()
                                .map(|v| range.satisfies(&v))
                        })
                        .unwrap_or(false);

                    if !satisfies {
                        warnings.push(PeerWarning {
                            package: canonical.clone(),
                            version: ver_str.clone(),
                            peer: peer_name.clone(),
                            required_range: peer_range_str.clone(),
                            resolved_version: Some(resolved_ver.clone()),
                        });
                    }
                }
                None => {
                    // Peer is completely missing from the resolved tree
                    warnings.push(PeerWarning {
                        package: canonical.clone(),
                        version: ver_str.clone(),
                        peer: peer_name.clone(),
                        required_range: peer_range_str.clone(),
                        resolved_version: None,
                    });
                }
            }
        }
    }

    // Sort for deterministic output
    warnings.sort_by(|a, b| a.package.cmp(&b.package).then(a.peer.cmp(&b.peer)));
    warnings
}

fn resolve_peer_version<'a>(
    consumer: &ResolverPackage,
    peer_name: &str,
    resolved_versions: &'a HashMap<String, Vec<(Option<String>, String)>>,
    unsplit_versions: &'a HashMap<String, String>,
) -> Option<&'a String> {
    let candidates = resolved_versions.get(peer_name)?;

    if let Some(context) = consumer.context()
        && let Some((_, version)) = candidates
            .iter()
            .find(|(candidate_context, _)| candidate_context.as_deref() == Some(context))
    {
        return Some(version);
    }

    if let Some(version) = unsplit_versions.get(peer_name) {
        return Some(version);
    }

    if candidates.len() == 1 {
        return Some(&candidates[0].1);
    }

    None
}

fn map_pubgrub_error(e: pubgrub::PubGrubError<LpmDependencyProvider>) -> ResolveError {
    match e {
        pubgrub::PubGrubError::NoSolution(mut dt) => {
            dt.collapse_no_versions();
            ResolveError::NoSolution(DefaultStringReporter::report(&dt))
        }
        pubgrub::PubGrubError::ErrorRetrievingDependencies {
            package,
            version,
            source,
        } => ResolveError::DependencyFetch {
            package: package.to_string(),
            version: version.to_string(),
            detail: source.to_string(),
        },
        pubgrub::PubGrubError::ErrorChoosingVersion { package, source } => {
            ResolveError::VersionChoice {
                package: package.to_string(),
                detail: source.to_string(),
            }
        }
        pubgrub::PubGrubError::ErrorInShouldCancel(e) => ResolveError::Cancelled(e.to_string()),
    }
}

/// Extract package names that appear in conflicts from PubGrub's error report.
///
/// Primary strategy: parse "X depends on PKG VERSION1 and Y depends on PKG VERSION2"
/// patterns. Fallback: extract all package-like names mentioned multiple times.
fn extract_conflicting_packages(report: &str) -> HashSet<String> {
    let conflicts = extract_conflicts_primary(report);
    if !conflicts.is_empty() {
        return conflicts;
    }

    // Fallback: primary extraction found nothing — PubGrub format may have changed
    tracing::warn!(
        "primary conflict extraction found no packages; falling back to broad extraction"
    );
    extract_conflicts_fallback(report)
}

/// Primary extraction: looks for "depends on PKG VERSION" patterns where PKG
/// appears with 2+ different version constraints.
fn extract_conflicts_primary(report: &str) -> HashSet<String> {
    let mut package_versions: HashMap<String, HashSet<String>> = HashMap::new();

    for line in report.lines() {
        let line = line.trim();
        let parts: Vec<&str> = line.split("depends on ").collect();
        for part in parts.iter().skip(1) {
            let tokens: Vec<&str> = part.split_whitespace().collect();
            if tokens.len() >= 2 {
                let pkg_name = tokens[0].trim_matches(',');
                let version = tokens[1].trim_matches(',');
                if !pkg_name.is_empty()
                    && !pkg_name.starts_with('<')
                    && version.chars().next().is_some_and(|c| c.is_ascii_digit())
                {
                    package_versions
                        .entry(pkg_name.to_string())
                        .or_default()
                        .insert(version.to_string());
                }
            }
        }
    }

    package_versions
        .into_iter()
        .filter(|(_, versions)| versions.len() >= 2)
        .map(|(name, _)| name)
        .collect()
}

/// Fallback extraction: find all tokens that look like package names
/// (contain only valid npm name chars) mentioned alongside version-like tokens.
/// Returns any package name that appears 2+ times in different contexts.
fn extract_conflicts_fallback(report: &str) -> HashSet<String> {
    let mut name_occurrences: HashMap<String, usize> = HashMap::new();

    for line in report.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for window in tokens.windows(2) {
            let candidate = window[0].trim_matches(|c: char| {
                !c.is_alphanumeric() && c != '@' && c != '/' && c != '.' && c != '-' && c != '_'
            });
            let next = window[1].trim_matches(',');
            // candidate looks like a package name, next looks like a version
            if !candidate.is_empty()
                && !candidate.starts_with('<')
                && !candidate.starts_with('>')
                && next.chars().next().is_some_and(|c| c.is_ascii_digit())
                && candidate
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '@' | '/' | '.' | '-' | '_'))
            {
                *name_occurrences.entry(candidate.to_string()).or_default() += 1;
            }
        }
    }

    // Return packages mentioned 2+ times as likely conflict participants
    name_occurrences
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(name, _)| name)
        .collect()
}

/// Errors from the resolution process.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no solution found:\n{0}")]
    NoSolution(String),

    #[error("failed to fetch dependencies for {package}@{version}: {detail}")]
    DependencyFetch {
        package: String,
        version: String,
        detail: String,
    },

    #[error("failed to choose version for {package}: {detail}")]
    VersionChoice { package: String, detail: String },

    #[error("resolution cancelled: {0}")]
    Cancelled(String),

    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Platform;
    use lpm_registry::{PackageMetadata, VersionMetadata};

    #[test]
    fn resolver_package_types_work() {
        let root = ResolverPackage::Root;
        assert!(root.is_root());

        let lpm = ResolverPackage::from_dep_name("@lpm.dev/neo.highlight");
        assert!(lpm.is_lpm());

        let npm = ResolverPackage::from_dep_name("react");
        assert!(npm.is_npm());
    }

    #[test]
    fn extract_conflicts_from_report() {
        let report = r#"
Because send 0.19.0 depends on ms 2.1.3 and debug 2.6.9 depends on ms 2.0.0,
send 0.19.0, debug 2.6.9 are incompatible.
"#;
        let conflicts = extract_conflicting_packages(report);
        assert!(conflicts.contains("ms"));
    }

    #[test]
    fn no_conflicts_in_primary_for_single_version() {
        // Primary extraction should NOT flag foo — it only appears with one version (1.0.0)
        let report = "Because root depends on foo 1.0.0 and foo 1.0.0 is not available.";
        let conflicts = extract_conflicts_primary(report);
        assert!(
            !conflicts.contains("foo"),
            "same version twice is not a conflict"
        );
    }

    #[test]
    fn primary_extraction_works() {
        let report = r#"
Because send 0.19.0 depends on ms 2.1.3 and debug 2.6.9 depends on ms 2.0.0,
send 0.19.0, debug 2.6.9 are incompatible.
"#;
        let conflicts = extract_conflicts_primary(report);
        assert!(conflicts.contains("ms"));
    }

    #[test]
    fn fallback_extraction_on_garbled_format() {
        // A format that doesn't use "depends on" but still mentions packages with versions
        let report = r#"
ms 2.1.3 is required by send 0.19.0
ms 2.0.0 is required by debug 2.6.9
these are incompatible
"#;
        // Primary should fail
        let primary = extract_conflicts_primary(report);
        assert!(
            primary.is_empty(),
            "primary should not find conflicts in non-standard format"
        );

        // Fallback should find ms (appears twice with different versions)
        let fallback = extract_conflicts_fallback(report);
        assert!(
            fallback.contains("ms"),
            "fallback should find 'ms' mentioned with 2+ versions"
        );
    }

    #[test]
    fn fallback_returns_nonempty_for_repeated_packages() {
        let report = "foo 1.0.0 conflicts with foo 2.0.0";
        let fallback = extract_conflicts_fallback(report);
        assert!(!fallback.is_empty(), "fallback should find something");
        assert!(fallback.contains("foo"));
    }

    // === Post-resolution peer dependency checking ===

    /// Helper to build a CachedPackageInfo for tests.
    fn make_cached_info(
        versions: &[&str],
        deps: Vec<(&str, Vec<(&str, &str)>)>,
        peer_deps: Vec<(&str, Vec<(&str, &str)>)>,
    ) -> CachedPackageInfo {
        CachedPackageInfo {
            versions: versions
                .iter()
                .map(|v| NpmVersion::parse(v).unwrap())
                .collect(),
            deps: deps
                .into_iter()
                .map(|(v, d)| {
                    (
                        v.to_string(),
                        d.into_iter()
                            .map(|(k, r)| (k.to_string(), r.to_string()))
                            .collect(),
                    )
                })
                .collect(),
            peer_deps: peer_deps
                .into_iter()
                .map(|(v, d)| {
                    (
                        v.to_string(),
                        d.into_iter()
                            .map(|(k, r)| (k.to_string(), r.to_string()))
                            .collect(),
                    )
                })
                .collect(),
            optional_dep_names: HashMap::new(),
            platform: HashMap::new(),
            dist: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    fn make_version_metadata(
        name: &str,
        version: &str,
        dependencies: Vec<(&str, &str)>,
        optional_dependencies: Vec<(&str, &str)>,
        os: Vec<&str>,
        cpu: Vec<&str>,
    ) -> VersionMetadata {
        VersionMetadata {
            name: name.to_string(),
            version: version.to_string(),
            dependencies: dependencies
                .into_iter()
                .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
                .collect(),
            optional_dependencies: optional_dependencies
                .into_iter()
                .map(|(dep_name, dep_range)| (dep_name.to_string(), dep_range.to_string()))
                .collect(),
            os: os.into_iter().map(str::to_string).collect(),
            cpu: cpu.into_iter().map(str::to_string).collect(),
            ..VersionMetadata::default()
        }
    }

    fn make_package_metadata(name: &str, versions: Vec<VersionMetadata>) -> PackageMetadata {
        let latest_version = versions
            .last()
            .map(|version| version.version.clone())
            .expect("package metadata test fixture needs at least one version");

        PackageMetadata {
            name: name.to_string(),
            description: None,
            dist_tags: HashMap::from([("latest".to_string(), latest_version.clone())]),
            versions: versions
                .into_iter()
                .map(|version| (version.version.clone(), version))
                .collect(),
            time: HashMap::new(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: Some(latest_version),
            ecosystem: None,
        }
    }

    #[tokio::test]
    async fn resolve_with_prefetch_skips_platform_incompatible_optional_registry_metadata() {
        let platform = Platform::current();
        let compatible_optional = format!("@esbuild/{}-{}", platform.os, platform.cpu);
        let (incompatible_optional, incompatible_os, incompatible_cpu) = if platform.os == "darwin"
        {
            ("@esbuild/linux-x64".to_string(), "linux", "x64")
        } else {
            ("@esbuild/darwin-arm64".to_string(), "darwin", "arm64")
        };

        let prefetched = HashMap::from([
            (
                "esbuild".to_string(),
                make_package_metadata(
                    "esbuild",
                    vec![make_version_metadata(
                        "esbuild",
                        "0.28.0",
                        vec![],
                        vec![
                            (compatible_optional.as_str(), "0.28.0"),
                            (incompatible_optional.as_str(), "0.28.0"),
                        ],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                compatible_optional.clone(),
                make_package_metadata(
                    &compatible_optional,
                    vec![make_version_metadata(
                        &compatible_optional,
                        "0.28.0",
                        vec![],
                        vec![],
                        vec![platform.os],
                        vec![platform.cpu],
                    )],
                ),
            ),
            (
                incompatible_optional.clone(),
                make_package_metadata(
                    &incompatible_optional,
                    vec![make_version_metadata(
                        &incompatible_optional,
                        "0.28.0",
                        vec![],
                        vec![],
                        vec![incompatible_os],
                        vec![incompatible_cpu],
                    )],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("esbuild".to_string(), "0.28.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("prefetched esbuild-style metadata should resolve on the current platform");

        let resolved_names: HashSet<String> = result
            .packages
            .iter()
            .map(|package| package.package.to_string())
            .collect();
        assert!(resolved_names.contains("esbuild"));
        assert!(resolved_names.contains(&compatible_optional));
        assert!(!resolved_names.contains(&incompatible_optional));

        let esbuild = result
            .packages
            .iter()
            .find(|package| package.package.canonical_name() == "esbuild")
            .expect("esbuild should be in the resolved tree");
        assert_eq!(
            esbuild.dependencies,
            vec![(compatible_optional, "0.28.0".to_string())]
        );
    }

    /// Phase 40 P3a — `StageTiming` contract: `resolve_with_prefetch`
    /// populates the field on `ResolveResult` and the resolver flows
    /// that value through the happy path to the caller.
    ///
    /// NOTE: The underlying counters live in `lpm_registry::timing`
    /// as process-global atomics (see that module's docs for why
    /// thread-locals can't work with `spawn_blocking`). Concurrent
    /// tests that trigger RPCs — even failing ones — will race on
    /// those atomics, so this test intentionally does NOT assert
    /// strict zeros on follow-up fields. The install-pipeline
    /// fixture run serves as the end-to-end contract check for
    /// non-zero values; here we validate only that the shape is
    /// wired through and that the `pubgrub_ms` accumulator ran
    /// (it's bounded by a single resolution pass, so not subject to
    /// cross-test contamination).
    #[tokio::test]
    async fn resolve_with_prefetch_emits_stage_timing_shape() {
        let prefetched = HashMap::from([
            (
                "app".to_string(),
                make_package_metadata(
                    "app",
                    vec![make_version_metadata(
                        "app",
                        "1.0.0",
                        vec![("left", "1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "left".to_string(),
                make_package_metadata(
                    "left",
                    vec![make_version_metadata(
                        "left",
                        "1.0.0",
                        vec![],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("app".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("fully-prefetched resolution must succeed");

        let t = result.stage_timing;
        // `pubgrub_ms` is a per-pass wall-clock accumulator, not a
        // process-global, so it's race-free. Even on the fastest
        // machines a non-trivial resolution is at least 1 instant
        // apart; but we tolerate 0 in case of sub-millisecond
        // resolution (the type is unsigned, so only assert upper
        // sanity bound).
        assert!(
            t.pubgrub_ms < 60_000,
            "pubgrub_ms of {} indicates runaway resolution or leaked wall-clock",
            t.pubgrub_ms
        );
        // Shape is accessible; follow-up fields exist and are read
        // without panic. The actual values are validated end-to-end
        // against a real install fixture.
        let _ = t.followup_rpc_ms;
        let _ = t.followup_rpc_count;
        let _ = t.parse_ndjson_ms;
    }

    /// Phase 40 P1 bug: a platform-gated optional dep has one old version with
    /// an ERRONEOUS `os`/`cpu` declaration that makes it look platform-compatible,
    /// but that version doesn't satisfy the declared range. The pre-P1 resolver
    /// passed this version through `available_versions` (because the platform
    /// filter matched), then produced an empty pubgrub `Ranges` (because the
    /// version was outside the range), which surfaced as a hard `NoSolution`
    /// error instead of an optional-dep skip.
    ///
    /// Real-world repro: `@next/swc-linux-x64-musl@12.0.0` ships with
    /// `os: ["darwin"]` (a Next.js packaging bug from 2021), but the declared
    /// range on `next@15.x` is `15.x`. The old `@next/swc-*` platform binaries
    /// are all in `optionalDependencies`, so bun/npm skip them cleanly; lpm
    /// blew up resolution.
    #[tokio::test]
    async fn resolve_with_prefetch_skips_optional_when_erroneous_platform_match_is_out_of_range() {
        let platform = Platform::current();
        let incompatible_optional = if platform.os == "darwin" {
            "@next/swc-linux-x64-musl".to_string()
        } else {
            "@next/swc-darwin-arm64".to_string()
        };

        // `next@15.5.15` declares `incompatible_optional: 15.5.15` as OPTIONAL.
        // The dep has two versions in the registry:
        //   - 15.5.15: declares the correct (incompatible) platform
        //   - 12.0.0: declares the current platform erroneously (Next.js packaging bug)
        // Neither of these should be installed on the current platform: 15.5.15
        // because the platform filter rejects it, 12.0.0 because the range
        // rejects it. Pre-P1 we blew up; post-P1 the whole optional dep is
        // skipped.
        let prefetched = HashMap::from([
            (
                "next".to_string(),
                make_package_metadata(
                    "next",
                    vec![make_version_metadata(
                        "next",
                        "15.5.15",
                        vec![],
                        vec![(incompatible_optional.as_str(), "15.5.15")],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                incompatible_optional.clone(),
                make_package_metadata(
                    &incompatible_optional,
                    vec![
                        // Correctly tagged for the OTHER platform — would be
                        // filtered by platform check.
                        make_version_metadata(
                            &incompatible_optional,
                            "15.5.15",
                            vec![],
                            vec![],
                            if platform.os == "darwin" {
                                vec!["linux"]
                            } else {
                                vec!["darwin"]
                            },
                            if platform.os == "darwin" {
                                vec!["x64"]
                            } else {
                                vec!["arm64"]
                            },
                        ),
                        // Erroneously tagged for the CURRENT platform — passes
                        // platform filter, but doesn't satisfy the declared
                        // range on `next@15.5.15` (which is `15.5.15` exactly).
                        make_version_metadata(
                            &incompatible_optional,
                            "12.0.0",
                            vec![],
                            vec![],
                            vec![platform.os],
                            vec![platform.cpu],
                        ),
                    ],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("next".to_string(), "15.5.15".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect(
            "resolver must skip optional dep when no platform-compatible version \
             satisfies the declared range (Next.js-style erroneous 12.0.0 version)",
        );

        let resolved_names: HashSet<String> = result
            .packages
            .iter()
            .map(|package| package.package.to_string())
            .collect();
        assert!(
            resolved_names.contains("next"),
            "root dep `next` must be resolved"
        );
        assert!(
            !resolved_names.contains(&incompatible_optional),
            "platform-gated optional dep must not be resolved even when an \
             erroneously-tagged version exists outside the declared range"
        );
        assert!(
            result.platform_skipped >= 1,
            "platform_skipped counter must record the skip for observability"
        );
    }

    /// Phase 40 P2 — npm-alias root dep: the consumer declares
    /// `"strip-ansi-cjs": "npm:strip-ansi@^6.0.1"`, and the resolver
    /// must (a) fetch `strip-ansi` metadata (not `strip-ansi-cjs`),
    /// (b) resolve the alias target's version against the inner range,
    /// and (c) surface the `local → target` mapping via
    /// `ResolveResult.root_aliases` so the install pipeline can build
    /// `node_modules/strip-ansi-cjs/` → `.lpm/strip-ansi@6.0.1/...`.
    #[tokio::test]
    async fn resolve_with_prefetch_handles_root_npm_alias() {
        let prefetched = HashMap::from([(
            "strip-ansi".to_string(),
            make_package_metadata(
                "strip-ansi",
                vec![make_version_metadata(
                    "strip-ansi",
                    "6.0.1",
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                )],
            ),
        )]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([(
                "strip-ansi-cjs".to_string(),
                "npm:strip-ansi@^6.0.1".to_string(),
            )]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("root npm-alias must resolve against the target identity");

        // The resolved tree contains the TARGET (`strip-ansi`), not the
        // alias key.
        let resolved_names: HashSet<String> = result
            .packages
            .iter()
            .map(|p| p.package.to_string())
            .collect();
        assert!(
            resolved_names.contains("strip-ansi"),
            "alias target must be in resolved tree"
        );
        assert!(
            !resolved_names.contains("strip-ansi-cjs"),
            "alias key must not pollute resolver identities"
        );

        // Root alias is surfaced for the install pipeline.
        assert_eq!(
            result.root_aliases.get("strip-ansi-cjs"),
            Some(&"strip-ansi".to_string()),
            "root_aliases must record local → target"
        );
    }

    /// Phase 40 P2 — npm-alias transitive dep: a parent package's
    /// registry metadata declares
    /// `"strip-ansi-cjs": "npm:strip-ansi@^6"` in its own
    /// `dependencies`. The resolver must treat the alias the same way
    /// at any depth — the parent's resolved edge list records the
    /// local name (`strip-ansi-cjs`), the resolved child is keyed on
    /// `strip-ansi`, and the parent's `aliases` map carries the
    /// `local → target` pair so the linker can build
    /// `.lpm/parent@1.0.0/node_modules/strip-ansi-cjs/` →
    /// `../../strip-ansi@6.0.1/node_modules/strip-ansi/`.
    #[tokio::test]
    async fn resolve_with_prefetch_handles_transitive_npm_alias() {
        let prefetched = HashMap::from([
            (
                "parent".to_string(),
                make_package_metadata(
                    "parent",
                    vec![make_version_metadata(
                        "parent",
                        "1.0.0",
                        vec![("strip-ansi-cjs", "npm:strip-ansi@^6")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "strip-ansi".to_string(),
                make_package_metadata(
                    "strip-ansi",
                    vec![make_version_metadata(
                        "strip-ansi",
                        "6.0.1",
                        vec![],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("parent".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("transitive npm-alias must resolve through the target identity");

        // Parent and aliased target (strip-ansi) are in the tree; the
        // alias key itself is NOT a distinct ResolverPackage.
        let resolved_names: HashSet<String> = result
            .packages
            .iter()
            .map(|p| p.package.to_string())
            .collect();
        assert!(resolved_names.contains("parent"));
        assert!(resolved_names.contains("strip-ansi"));
        assert!(!resolved_names.contains("strip-ansi-cjs"));

        // Parent's dep edge carries the LOCAL name + resolved version.
        let parent = result
            .packages
            .iter()
            .find(|p| p.package.canonical_name() == "parent")
            .unwrap();
        assert_eq!(
            parent.dependencies,
            vec![("strip-ansi-cjs".to_string(), "6.0.1".to_string())],
            "edge key is the local alias name, version is the target's"
        );
        assert_eq!(
            parent.aliases.get("strip-ansi-cjs"),
            Some(&"strip-ansi".to_string()),
            "parent's aliases map records local → target"
        );

        // Transitive aliases are NOT root aliases.
        assert!(
            result.root_aliases.is_empty(),
            "transitive alias must not leak into the root alias map"
        );
    }

    /// Regression: a non-optional dep with no platform-compatible version
    /// still fails (doesn't silently skip). Protects against accidentally
    /// extending Phase 40 P1's optional-skip to regular deps, which would
    /// hide real bugs (e.g., a package that declared os: ["win32"] for a
    /// regular dep on linux must still surface as a resolution failure).
    #[tokio::test]
    async fn resolve_regular_dep_with_no_platform_compatible_version_still_fails() {
        let platform = Platform::current();
        let incompatible_dep = if platform.os == "darwin" {
            "some-linux-only-dep".to_string()
        } else {
            "some-darwin-only-dep".to_string()
        };

        let prefetched = HashMap::from([
            (
                "app".to_string(),
                make_package_metadata(
                    "app",
                    vec![make_version_metadata(
                        "app",
                        "1.0.0",
                        vec![(incompatible_dep.as_str(), "1.0.0")], // REQUIRED dep
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                incompatible_dep.clone(),
                make_package_metadata(
                    &incompatible_dep,
                    vec![make_version_metadata(
                        &incompatible_dep,
                        "1.0.0",
                        vec![],
                        vec![],
                        if platform.os == "darwin" {
                            vec!["linux"]
                        } else {
                            vec!["darwin"]
                        },
                        vec![],
                    )],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("app".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await;

        assert!(
            result.is_err(),
            "regular dep with no platform-compatible version must still fail resolution; \
             optional-skip semantics must not leak into required deps"
        );
    }

    #[tokio::test]
    async fn resolve_with_prefetch_retries_until_all_conflicts_are_split() {
        let prefetched = HashMap::from([
            (
                "app".to_string(),
                make_package_metadata(
                    "app",
                    vec![make_version_metadata(
                        "app",
                        "1.0.0",
                        vec![("a", "1.0.0"), ("b", "1.0.0"), ("c", "1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "a".to_string(),
                make_package_metadata(
                    "a",
                    vec![make_version_metadata(
                        "a",
                        "1.0.0",
                        vec![("x", "1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "b".to_string(),
                make_package_metadata(
                    "b",
                    vec![make_version_metadata(
                        "b",
                        "1.0.0",
                        vec![("x", "2.0.0"), ("y", "1.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "c".to_string(),
                make_package_metadata(
                    "c",
                    vec![make_version_metadata(
                        "c",
                        "1.0.0",
                        vec![("y", "2.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "x".to_string(),
                make_package_metadata(
                    "x",
                    vec![
                        make_version_metadata("x", "1.0.0", vec![], vec![], vec![], vec![]),
                        make_version_metadata("x", "2.0.0", vec![], vec![], vec![], vec![]),
                    ],
                ),
            ),
            (
                "y".to_string(),
                make_package_metadata(
                    "y",
                    vec![
                        make_version_metadata("y", "1.0.0", vec![], vec![], vec![], vec![]),
                        make_version_metadata("y", "2.0.0", vec![], vec![], vec![], vec![]),
                    ],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("app".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect("resolver should keep splitting until both x and y conflicts are scoped");

        let resolved_versions: HashMap<String, String> = result
            .packages
            .iter()
            .map(|package| (package.package.to_string(), package.version.to_string()))
            .collect();

        assert_eq!(
            resolved_versions.get("x[a]").map(String::as_str),
            Some("1.0.0")
        );
        assert_eq!(
            resolved_versions.get("x[b]").map(String::as_str),
            Some("2.0.0")
        );
        assert_eq!(
            resolved_versions.get("y[b]").map(String::as_str),
            Some("1.0.0")
        );
        assert_eq!(
            resolved_versions.get("y[c]").map(String::as_str),
            Some("2.0.0")
        );
    }

    /// Phase 40 P4 — nested-scope propagation.
    ///
    /// Minimal reproduction of the real-world eslint + ajv conflict:
    /// root depends on ajv@^8 + eslint@^9; eslint@9 transitively requires
    /// ajv@^6; ajv@8 and ajv@6 each declare DIFFERENT json-schema-traverse
    /// version ranges.
    ///
    /// bun resolves this fine — two ajv's coexist in node_modules (top-
    /// level ajv@8 + nested eslint/node_modules/ajv@6), each with its own
    /// json-schema-traverse.
    ///
    /// Before the fix, lpm's pubgrub concluded NoSolution because the
    /// split-retry logic could split `ajv` into `ajv[<root>]` vs
    /// `ajv[eslint]`, but when enumerating the split ajv's deps the scope
    /// key for the grandchild was built from
    /// `parent.canonical_name()` — which strips the parent's context.
    /// Both ajv's produced a child scope-key of `[ajv]`, unifying the two
    /// json-schema-traverse requests back into a single pubgrub identity
    /// whose version ranges collided.
    ///
    /// After the fix, the grandchild scope key is derived from the
    /// parent's full display identity, so `ajv[<root>]`'s child gets
    /// `json-schema-traverse[ajv[<root>]]` and `ajv[eslint]`'s child gets
    /// `json-schema-traverse[ajv[eslint]]` — distinct pubgrub packages,
    /// each able to satisfy its own range.
    #[tokio::test]
    async fn resolve_with_prefetch_propagates_parent_context_to_grandchild_splits() {
        let prefetched = HashMap::from([
            (
                "root_app".to_string(),
                make_package_metadata(
                    "root_app",
                    vec![make_version_metadata(
                        "root_app",
                        "1.0.0",
                        vec![("ajv", "^8.0.0"), ("eslint", "^9.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "eslint".to_string(),
                make_package_metadata(
                    "eslint",
                    vec![make_version_metadata(
                        "eslint",
                        "9.0.0",
                        vec![("ajv", "^6.0.0")],
                        vec![],
                        vec![],
                        vec![],
                    )],
                ),
            ),
            (
                "ajv".to_string(),
                make_package_metadata(
                    "ajv",
                    vec![
                        make_version_metadata(
                            "ajv",
                            "6.14.0",
                            vec![("json-schema-traverse", "^0.4.0")],
                            vec![],
                            vec![],
                            vec![],
                        ),
                        make_version_metadata(
                            "ajv",
                            "8.18.0",
                            vec![("json-schema-traverse", "^1.0.0")],
                            vec![],
                            vec![],
                            vec![],
                        ),
                    ],
                ),
            ),
            (
                "json-schema-traverse".to_string(),
                make_package_metadata(
                    "json-schema-traverse",
                    vec![
                        make_version_metadata(
                            "json-schema-traverse",
                            "0.4.1",
                            vec![],
                            vec![],
                            vec![],
                            vec![],
                        ),
                        make_version_metadata(
                            "json-schema-traverse",
                            "1.0.0",
                            vec![],
                            vec![],
                            vec![],
                            vec![],
                        ),
                    ],
                ),
            ),
        ]);

        let result = resolve_with_prefetch(
            Arc::new(lpm_registry::RegistryClient::new().with_base_url("http://127.0.0.1:9")),
            HashMap::from([("root_app".to_string(), "1.0.0".to_string())]),
            OverrideSet::empty(),
            Some(prefetched),
        )
        .await
        .expect(
            "resolver must handle eslint+ajv nested duplicates — bun and npm both resolve this \
             without dropping deps",
        );

        let resolved_versions: HashMap<String, String> = result
            .packages
            .iter()
            .map(|package| (package.package.to_string(), package.version.to_string()))
            .collect();

        // Two ajv's must coexist.
        let ajv_8_key = resolved_versions
            .iter()
            .find(|(_, v)| v.as_str() == "8.18.0")
            .map(|(k, _)| k.clone())
            .expect("ajv@8 should be chosen for the root's direct ^8 range");
        let ajv_6_key = resolved_versions
            .iter()
            .find(|(_, v)| v.as_str() == "6.14.0")
            .map(|(k, _)| k.clone())
            .expect("ajv@6 should be chosen for eslint's transitive ^6 range");
        assert!(
            ajv_8_key.starts_with("ajv"),
            "ajv@8 key should be an ajv identity, got {ajv_8_key}"
        );
        assert!(
            ajv_6_key.starts_with("ajv"),
            "ajv@6 key should be an ajv identity, got {ajv_6_key}"
        );
        assert_ne!(
            ajv_8_key, ajv_6_key,
            "ajv@8 and ajv@6 must be distinct pubgrub identities, both got {ajv_8_key}"
        );

        // And both json-schema-traverse versions must coexist, one per ajv.
        let mut jst_versions: Vec<&str> = resolved_versions
            .iter()
            .filter(|(k, _)| k.starts_with("json-schema-traverse"))
            .map(|(_, v)| v.as_str())
            .collect();
        jst_versions.sort();
        assert_eq!(
            jst_versions,
            vec!["0.4.1", "1.0.0"],
            "exactly one json-schema-traverse@0.4.1 and one @1.0.0 must resolve — got {:?}",
            resolved_versions
        );
    }

    #[test]
    fn peer_check_satisfied_peer_no_warning() {
        // styled-components@5.0.0 peers on react@^16||^17
        // react@17.0.2 is in the tree → satisfied, no warning
        let sc_pkg = ResolverPackage::npm("styled-components");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: sc_pkg.clone(),
                version: NpmVersion::parse("5.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            sc_pkg,
            make_cached_info(
                &["5.0.0"],
                vec![],
                vec![("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")])],
            ),
        );
        cache.insert(react_pkg, make_cached_info(&["17.0.2"], vec![], vec![]));

        let warnings = check_unmet_peers(&resolved, &cache);
        assert!(
            warnings.is_empty(),
            "peer should be satisfied: {warnings:?}"
        );
    }

    #[test]
    fn peer_check_wrong_version_produces_warning() {
        // styled-components@6.0.0 peers on react@^18
        // react@17.0.2 is in the tree → version mismatch warning
        let sc_pkg = ResolverPackage::npm("styled-components");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: sc_pkg.clone(),
                version: NpmVersion::parse("6.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            sc_pkg,
            make_cached_info(
                &["6.0.0"],
                vec![],
                vec![("6.0.0", vec![("react", "^18.0.0")])],
            ),
        );
        cache.insert(react_pkg, make_cached_info(&["17.0.2"], vec![], vec![]));

        let warnings = check_unmet_peers(&resolved, &cache);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].peer, "react");
        assert_eq!(warnings[0].required_range, "^18.0.0");
        assert_eq!(warnings[0].resolved_version.as_deref(), Some("17.0.2"));
    }

    #[test]
    fn peer_check_missing_peer_produces_warning() {
        // styled-components@5.0.0 peers on react@^16||^17
        // react is NOT in the tree → missing peer warning
        let sc_pkg = ResolverPackage::npm("styled-components");

        let resolved = vec![ResolvedPackage {
            package: sc_pkg.clone(),
            version: NpmVersion::parse("5.0.0").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            tarball_url: None,
            integrity: None,
        }];

        let mut cache = HashMap::new();
        cache.insert(
            sc_pkg,
            make_cached_info(
                &["5.0.0"],
                vec![],
                vec![("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")])],
            ),
        );

        let warnings = check_unmet_peers(&resolved, &cache);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].peer, "react");
        assert!(
            warnings[0].resolved_version.is_none(),
            "peer is missing from tree"
        );
    }

    #[test]
    fn peer_check_version_specific_no_cross_contamination() {
        // Key test: styled-components has different peers per version.
        // Only the SELECTED version's peers should be checked.
        //
        // v5.0.0 peers on react@^16||^17
        // v6.0.0 peers on react@^18
        //
        // If v5.0.0 is selected and react@17.0.2 is in tree:
        //   → NO warning (^16||^17 satisfied by 17.0.2)
        //
        // The old union approach would have forced react@^18 (newest wins),
        // which would incorrectly fail.
        let sc_pkg = ResolverPackage::npm("styled-components");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: sc_pkg.clone(),
                version: NpmVersion::parse("5.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
        ];

        let mut cache = HashMap::new();
        // Both versions are in cache, but only v5's peers should matter
        cache.insert(
            sc_pkg,
            make_cached_info(
                &["6.0.0", "5.0.0"],
                vec![],
                vec![
                    ("5.0.0", vec![("react", "^16.8.0 || ^17.0.0")]),
                    ("6.0.0", vec![("react", "^18.0.0")]),
                ],
            ),
        );
        cache.insert(react_pkg, make_cached_info(&["17.0.2"], vec![], vec![]));

        let warnings = check_unmet_peers(&resolved, &cache);
        assert!(
            warnings.is_empty(),
            "v5's peer react@^16||^17 is satisfied by 17.0.2, v6's peers should not apply: {warnings:?}"
        );
    }

    #[test]
    fn peer_check_prefers_same_split_context_peer_version() {
        let plugin_pkg = ResolverPackage::npm("plugin").with_context("host-a");
        let react_host_a = ResolverPackage::npm("react").with_context("host-a");
        let react_host_b = ResolverPackage::npm("react").with_context("host-b");

        let resolved = vec![
            ResolvedPackage {
                package: plugin_pkg.clone(),
                version: NpmVersion::parse("1.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_host_a.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_host_b.clone(),
                version: NpmVersion::parse("18.2.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
        ];

        let mut cache = HashMap::new();
        cache.insert(
            plugin_pkg,
            make_cached_info(
                &["1.0.0"],
                vec![],
                vec![("1.0.0", vec![("react", "^17.0.0")])],
            ),
        );
        cache.insert(react_host_a, make_cached_info(&["17.0.2"], vec![], vec![]));
        cache.insert(react_host_b, make_cached_info(&["18.2.0"], vec![], vec![]));

        let warnings = check_unmet_peers(&resolved, &cache);
        assert!(
            warnings.is_empty(),
            "split package should use peer version from the same context before falling back globally: {warnings:?}"
        );
    }

    #[test]
    fn peer_check_multiple_packages_multiple_peers() {
        // Two packages with different peers
        let pkg_a = ResolverPackage::npm("pkg-a");
        let pkg_b = ResolverPackage::npm("pkg-b");
        let react_pkg = ResolverPackage::npm("react");

        let resolved = vec![
            ResolvedPackage {
                package: pkg_a.clone(),
                version: NpmVersion::parse("1.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: pkg_b.clone(),
                version: NpmVersion::parse("2.0.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("18.2.0").unwrap(),
                dependencies: vec![],
                aliases: HashMap::new(),
                tarball_url: None,
                integrity: None,
            },
        ];

        let mut cache = HashMap::new();
        // pkg-a peers on react@^18 (satisfied) and vue@^3 (missing)
        cache.insert(
            pkg_a,
            make_cached_info(
                &["1.0.0"],
                vec![],
                vec![("1.0.0", vec![("react", "^18.0.0"), ("vue", "^3.0.0")])],
            ),
        );
        // pkg-b peers on react@^17 (wrong version)
        cache.insert(
            pkg_b,
            make_cached_info(
                &["2.0.0"],
                vec![],
                vec![("2.0.0", vec![("react", "^17.0.0")])],
            ),
        );
        cache.insert(react_pkg, make_cached_info(&["18.2.0"], vec![], vec![]));

        let warnings = check_unmet_peers(&resolved, &cache);
        // Should have 2 warnings: vue missing + react wrong version for pkg-b
        assert_eq!(warnings.len(), 2, "expected 2 warnings: {warnings:?}");

        // Sorted by package then peer
        assert_eq!(warnings[0].package, "pkg-a");
        assert_eq!(warnings[0].peer, "vue");
        assert!(warnings[0].resolved_version.is_none());

        assert_eq!(warnings[1].package, "pkg-b");
        assert_eq!(warnings[1].peer, "react");
        assert_eq!(warnings[1].resolved_version.as_deref(), Some("18.2.0"));
    }

    #[test]
    fn peer_check_no_peers_no_warnings() {
        // Package with no peer deps → no warnings
        let pkg = ResolverPackage::npm("lodash");

        let resolved = vec![ResolvedPackage {
            package: pkg.clone(),
            version: NpmVersion::parse("4.17.21").unwrap(),
            dependencies: vec![],
            aliases: HashMap::new(),
            tarball_url: None,
            integrity: None,
        }];

        let mut cache = HashMap::new();
        cache.insert(pkg, make_cached_info(&["4.17.21"], vec![], vec![]));

        let warnings = check_unmet_peers(&resolved, &cache);
        assert!(warnings.is_empty());
    }

    #[test]
    fn peer_warning_display_format() {
        let w_missing = PeerWarning {
            package: "styled-components".to_string(),
            version: "5.0.0".to_string(),
            peer: "react".to_string(),
            required_range: "^16.8.0".to_string(),
            resolved_version: None,
        };
        assert!(w_missing.to_string().contains("is not installed"));

        let w_wrong = PeerWarning {
            package: "styled-components".to_string(),
            version: "6.0.0".to_string(),
            peer: "react".to_string(),
            required_range: "^18.0.0".to_string(),
            resolved_version: Some("17.0.2".to_string()),
        };
        assert!(w_wrong.to_string().contains("17.0.2 was resolved"));
    }
}
