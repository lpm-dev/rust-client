//! High-level resolution entry point.
//!
//! Two-phase approach:
//! 1. Try flat resolution (one version per package) — works for ~90% of real trees
//! 2. On conflict, identify packages needing multiple versions, re-resolve with splits

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
    /// Dependencies of this package: (dep_canonical_name, resolved_version_string).
    /// Populated from the resolver's cached metadata so the install pipeline
    /// knows which packages each resolved entry depends on.
    pub dependencies: Vec<(String, String)>,
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
}

/// Resolve dependencies for a project.
///
/// Uses a two-phase approach:
/// 1. Flat resolution with PubGrub (one version per package)
/// 2. If that fails due to version conflicts, identify the conflicting packages
///    and re-resolve with split identities (allowing multiple versions)
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
/// fall through to Phase 2 (split-on-conflict) for an override to take
/// effect. Phase 2 still inherits the same set so any conflict-driven
/// splits union with the override-driven ones.
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

    // Phase 34.4: reset profiling accumulators once before either pass.
    // Counters accumulate across Phase 1 + Phase 2 (if split retry happens)
    // so the final summary reflects ALL resolver work, not just one pass.
    crate::profile::reset_all();

    // Pre-compute the split set from path selectors. Empty when no
    // path-selector overrides are declared, which keeps the no-overrides
    // path on the existing zero-allocation hot loop.
    let initial_splits: HashSet<String> = overrides.split_targets().clone();

    // Phase 1: Flat resolution (with optional override-driven splits)
    let deps_clone = dependencies.clone();
    let client_clone = client.clone();
    let rt_clone = rt.clone();
    let overrides_clone = overrides.clone();
    let initial_splits_clone = initial_splits.clone();

    let result: PubGrubResult = tokio::task::spawn_blocking(move || {
        let mut provider = if initial_splits_clone.is_empty() {
            LpmDependencyProvider::new(client_clone, rt_clone, deps_clone)
        } else {
            LpmDependencyProvider::new_with_splits(
                client_clone,
                rt_clone,
                deps_clone,
                initial_splits_clone,
            )
        }
        .with_overrides(overrides_clone);
        // Phase 34.5: pre-seed in-memory cache from batch prefetch results
        if let Some(batch) = prefetched {
            provider = provider.with_prefetched_metadata(&batch);
        }
        match pubgrub::resolve(&provider, ResolverPackage::Root, NpmVersion::new(0, 0, 0)) {
            Ok(solution) => Ok((solution, provider)),
            Err(e) => Err(Box::new((e, provider))),
        }
    })
    .await
    .map_err(|e| ResolveError::Internal(format!("resolver task panicked: {e}")))?;

    let final_result = match result {
        Ok((solution, provider)) => {
            let (cache, applied_overrides) = provider.into_parts();
            let packages = format_solution(solution, &cache);
            Ok(ResolveResult {
                packages,
                cache,
                applied_overrides,
            })
        }
        Err(err) if matches!(err.0, pubgrub::PubGrubError::NoSolution(_)) => {
            let (pubgrub::PubGrubError::NoSolution(mut derivation_tree), phase1_provider) = *err
            else {
                unreachable!()
            };
            // Phase 2: Extract conflicting packages and try split resolution
            derivation_tree.collapse_no_versions();
            let report = DefaultStringReporter::report(&derivation_tree);

            let mut conflicting = extract_conflicting_packages(&report);
            if conflicting.is_empty() {
                // Phase 34.4: dump even on early error exit
                tracing::debug!(
                    "resolver profile (phase 1 only, no split candidates):\n{}",
                    crate::profile::summary()
                );
                return Err(ResolveError::NoSolution(report));
            }
            // Union the conflict-driven splits with the override-driven
            // splits so the second pass keeps the path-selector splits
            // alive even if Phase 1 didn't trip on them.
            conflicting.extend(initial_splits.iter().cloned());

            tracing::info!(
                "flat resolution failed, splitting {} package(s): {}",
                conflicting.len(),
                conflicting.iter().cloned().collect::<Vec<_>>().join(", ")
            );

            // Carry Phase 1's metadata cache into Phase 2 so split resolution
            // doesn't re-parse all package metadata from disk. Every package
            // that Phase 1 already fetched becomes an instant in-memory hit.
            let phase1_cache = phase1_provider.into_cache();

            // Phase 2: Re-resolve with split packages
            let result2: PubGrubResult = tokio::task::spawn_blocking(move || {
                let provider =
                    LpmDependencyProvider::new_with_splits(client, rt, dependencies, conflicting)
                        .with_overrides(overrides)
                        .with_cache(phase1_cache);
                match pubgrub::resolve(&provider, ResolverPackage::Root, NpmVersion::new(0, 0, 0)) {
                    Ok(solution) => Ok((solution, provider)),
                    Err(e) => Err(Box::new((e, provider))),
                }
            })
            .await
            .map_err(|e| ResolveError::Internal(format!("split resolver panicked: {e}")))?;

            match result2 {
                Ok((solution, provider)) => {
                    let (cache, applied_overrides) = provider.into_parts();
                    let packages = format_solution(solution, &cache);
                    Ok(ResolveResult {
                        packages,
                        cache,
                        applied_overrides,
                    })
                }
                Err(err) if matches!(err.0, pubgrub::PubGrubError::NoSolution(_)) => {
                    let (pubgrub::PubGrubError::NoSolution(mut dt), _) = *err else {
                        unreachable!()
                    };
                    dt.collapse_no_versions();
                    Err(ResolveError::NoSolution(DefaultStringReporter::report(&dt)))
                }
                Err(err) => Err(map_pubgrub_error(err.0)),
            }
        }
        Err(err) => Err(map_pubgrub_error(err.0)),
    };

    // Phase 34.4: dump cumulative resolver profile AFTER all passes complete.
    // Counters accumulate across Phase 1 + Phase 2 (split retry).
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

            // Look up this package's declared deps from the provider cache
            let dependencies = cache
                .get(&package)
                .and_then(|info| info.deps.get(&ver_str))
                .map(|ver_deps| {
                    ver_deps
                        .keys()
                        .filter_map(|dep_name| {
                            // Find the resolved version for this dep
                            resolved_versions
                                .get(dep_name)
                                .map(|resolved_ver| (dep_name.clone(), resolved_ver.clone()))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

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
        }
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
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
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
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
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
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
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
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_host_a.clone(),
                version: NpmVersion::parse("17.0.2").unwrap(),
                dependencies: vec![],
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_host_b.clone(),
                version: NpmVersion::parse("18.2.0").unwrap(),
                dependencies: vec![],
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
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: pkg_b.clone(),
                version: NpmVersion::parse("2.0.0").unwrap(),
                dependencies: vec![],
                tarball_url: None,
                integrity: None,
            },
            ResolvedPackage {
                package: react_pkg.clone(),
                version: NpmVersion::parse("18.2.0").unwrap(),
                dependencies: vec![],
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
