//! High-level resolution entry point.
//!
//! Two-phase approach:
//! 1. Try flat resolution (one version per package) — works for ~90% of real trees
//! 2. On conflict, identify packages needing multiple versions, re-resolve with splits

use crate::npm_version::NpmVersion;
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
}

/// Internal type for PubGrub result + provider (to extract cache).
type PubGrubResult = Result<
    (
        pubgrub::SelectedDependencies<LpmDependencyProvider>,
        LpmDependencyProvider,
    ),
    (
        pubgrub::PubGrubError<LpmDependencyProvider>,
        LpmDependencyProvider,
    ),
>;

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
) -> Result<Vec<ResolvedPackage>, ResolveError> {
    resolve_dependencies_with_overrides(client, dependencies, HashMap::new()).await
}

/// Resolve with optional version overrides from package.json.
pub async fn resolve_dependencies_with_overrides(
    client: Arc<RegistryClient>,
    dependencies: HashMap<String, String>,
    overrides: HashMap<String, String>,
) -> Result<Vec<ResolvedPackage>, ResolveError> {
    let rt = Handle::current();

    // Phase 1: Flat resolution
    let deps_clone = dependencies.clone();
    let client_clone = client.clone();
    let rt_clone = rt.clone();
    let overrides_clone = overrides.clone();

    let result: PubGrubResult = tokio::task::spawn_blocking(move || {
        let provider = LpmDependencyProvider::new(client_clone, rt_clone, deps_clone)
            .with_overrides(overrides_clone);
        match pubgrub::resolve(&provider, ResolverPackage::Root, NpmVersion::new(0, 0, 0)) {
            Ok(solution) => Ok((solution, provider)),
            Err(e) => Err((e, provider)),
        }
    })
    .await
    .map_err(|e| ResolveError::Internal(format!("resolver task panicked: {e}")))?;

    match result {
        Ok((solution, provider)) => {
            let cache = provider.into_cache();
            Ok(format_solution(solution, &cache))
        }
        Err((pubgrub::PubGrubError::NoSolution(mut derivation_tree), _provider)) => {
            // Phase 2: Extract conflicting packages and try split resolution
            derivation_tree.collapse_no_versions();
            let report = DefaultStringReporter::report(&derivation_tree);

            let conflicting = extract_conflicting_packages(&report);
            if conflicting.is_empty() {
                return Err(ResolveError::NoSolution(report));
            }

            tracing::info!(
                "flat resolution failed, splitting {} package(s): {}",
                conflicting.len(),
                conflicting.iter().cloned().collect::<Vec<_>>().join(", ")
            );

            // Phase 2: Re-resolve with split packages
            let result2: PubGrubResult = tokio::task::spawn_blocking(move || {
                let provider = LpmDependencyProvider::new_with_splits(
                    client,
                    rt,
                    dependencies,
                    conflicting,
                )
                .with_overrides(overrides);
                match pubgrub::resolve(
                    &provider,
                    ResolverPackage::Root,
                    NpmVersion::new(0, 0, 0),
                ) {
                    Ok(solution) => Ok((solution, provider)),
                    Err(e) => Err((e, provider)),
                }
            })
            .await
            .map_err(|e| ResolveError::Internal(format!("split resolver panicked: {e}")))?;

            match result2 {
                Ok((solution, provider)) => {
                    let cache = provider.into_cache();
                    Ok(format_solution(solution, &cache))
                }
                Err((pubgrub::PubGrubError::NoSolution(mut dt), _)) => {
                    dt.collapse_no_versions();
                    Err(ResolveError::NoSolution(DefaultStringReporter::report(&dt)))
                }
                Err((e, _)) => Err(map_pubgrub_error(e)),
            }
        }
        Err((e, _)) => Err(map_pubgrub_error(e)),
    }
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

            ResolvedPackage {
                package,
                version,
                dependencies,
            }
        })
        .collect();
    resolved.sort_by(|a, b| a.package.to_string().cmp(&b.package.to_string()));
    resolved
}

fn map_pubgrub_error(
    e: pubgrub::PubGrubError<LpmDependencyProvider>,
) -> ResolveError {
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
        pubgrub::PubGrubError::ErrorInShouldCancel(e) => {
            ResolveError::Cancelled(e.to_string())
        }
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
            let candidate = window[0].trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '/' && c != '.' && c != '-' && c != '_');
            let next = window[1].trim_matches(',');
            // candidate looks like a package name, next looks like a version
            if !candidate.is_empty()
                && !candidate.starts_with('<')
                && !candidate.starts_with('>')
                && next.chars().next().is_some_and(|c| c.is_ascii_digit())
                && candidate.chars().all(|c| c.is_alphanumeric() || matches!(c, '@' | '/' | '.' | '-' | '_'))
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
        assert!(!conflicts.contains("foo"), "same version twice is not a conflict");
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
        assert!(primary.is_empty(), "primary should not find conflicts in non-standard format");

        // Fallback should find ms (appears twice with different versions)
        let fallback = extract_conflicts_fallback(report);
        assert!(fallback.contains("ms"), "fallback should find 'ms' mentioned with 2+ versions");
    }

    #[test]
    fn fallback_returns_nonempty_for_repeated_packages() {
        let report = "foo 1.0.0 conflicts with foo 2.0.0";
        let fallback = extract_conflicts_fallback(report);
        assert!(!fallback.is_empty(), "fallback should find something");
        assert!(fallback.contains("foo"));
    }
}
