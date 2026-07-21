use super::prelude::*;
use lpm_common::{ResolutionErrorContext, ResolutionFailureKind};

pub(super) fn map_pubgrub_error(e: pubgrub::PubGrubError<LpmDependencyProvider>) -> ResolveError {
    match e {
        pubgrub::PubGrubError::NoSolution(mut dt) => {
            dt.collapse_no_versions();
            no_solution_error(DefaultStringReporter::report(&dt))
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

pub(super) fn no_solution_error(report: String) -> ResolveError {
    ResolveError::Resolution(Box::new(ResolutionErrorContext {
        package: "dependency graph".to_string(),
        requested: "*".to_string(),
        dependency: "dependency graph".to_string(),
        required_by: None,
        kind: ResolutionFailureKind::NoSolution,
        reason: "no compatible set of package versions exists".to_string(),
        available_versions: None,
        newest_version: None,
        derivation: Some(report),
    }))
}

/// Extract package names that appear in conflicts from PubGrub's error report.
///
/// Primary strategy: parse "X depends on PKG VERSION1 and Y depends on PKG VERSION2"
/// patterns. Fallback: extract all package-like names mentioned multiple times.
pub(super) fn extract_conflicting_packages(report: &str) -> HashSet<String> {
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
pub(super) fn extract_conflicts_primary(report: &str) -> HashSet<String> {
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
pub(super) fn extract_conflicts_fallback(report: &str) -> HashSet<String> {
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
    #[error("{0}")]
    Resolution(Box<ResolutionErrorContext>),

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

    #[error(
        "invalid peer dependency specifier {specifier:?} for `{peer}` declared by {consumer}@{version}: {detail}"
    )]
    InvalidPeerSpecifier {
        consumer: String,
        version: String,
        peer: String,
        specifier: String,
        detail: String,
    },

    #[error(
        "cannot auto-install required peer `{peer}` declared by {consumer}: specifier {specifier:?} uses unsupported `{scheme}:` source routing; install a compatible provider explicitly or disable peer auto-installation"
    )]
    UnsupportedPeerAutoInstallSource {
        consumer: String,
        peer: String,
        specifier: String,
        scheme: String,
    },

    /// Two or more consumers in the install set declare
    /// `peerDependencies` for `canonical` whose ranges have no version
    /// in common, AND at least one of those consumers is non-optional.
    /// The auto-install path can't pick a single version that satisfies
    /// every required consumer's range.
    ///
    /// `requirements` lists every contributing consumer with its
    /// declared range so the user can act on the conflict (typically:
    /// pin a version of one of the consumers, or use
    /// `lpm.overrides` to force a peer version).
    ///
    /// **Why this is an error and not a warning:** the alternative
    /// (warn-only post-resolve) leaves the install in a half-broken
    /// state where one consumer silently gets a peer that doesn't
    /// satisfy its declared range. An unsatisfiable peer with at least
    /// one required consumer has the same shape as
    /// [`Self::NoSolution`] for regular deps.
    #[error(
        "peer dependency conflict for `{canonical}`: {} consumer(s) declare incompatible ranges. \
         Consumers: {}",
        requirements.len(),
        format_peer_conflict_consumers(requirements)
    )]
    PeerConflict {
        /// Registry identity of the conflicted peer.
        canonical: String,
        /// One entry per contributing consumer:
        /// `(consumer_canonical, declared_range, optional)`.
        requirements: Vec<(String, String, bool)>,
    },
}

/// Format the `requirements` list on a [`ResolveError::PeerConflict`]
/// for the `Display` impl. Sorted deterministically by `(consumer
/// name, range)` so two failing runs produce byte-identical error
/// messages regardless of `HashMap` iteration order.
fn format_peer_conflict_consumers(reqs: &[(String, String, bool)]) -> String {
    let mut sorted: Vec<&(String, String, bool)> = reqs.iter().collect();
    sorted.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    sorted
        .iter()
        .map(|(consumer, range, optional)| {
            if *optional {
                format!("{consumer} → {range} (optional)")
            } else {
                format!("{consumer} → {range}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}
