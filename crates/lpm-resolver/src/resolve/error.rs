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
    let mut package_versions: HashMap<&str, HashSet<&str>> = HashMap::new();

    for line in report.lines() {
        let line = line.trim();
        for part in line.split("depends on ").skip(1) {
            let mut tokens = part.split_whitespace();
            let (Some(raw_pkg), Some(raw_ver)) = (tokens.next(), tokens.next()) else {
                continue;
            };
            let pkg_name = raw_pkg.trim_matches(',');
            let version = raw_ver.trim_matches(',');
            if !pkg_name.is_empty()
                && !pkg_name.starts_with('<')
                && version.as_bytes().first().is_some_and(u8::is_ascii_digit)
            {
                package_versions
                    .entry(pkg_name)
                    .or_default()
                    .insert(version);
            }
        }
    }

    package_versions
        .into_iter()
        .filter(|(_, versions)| versions.len() >= 2)
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// Fallback extraction: find all tokens that look like package names
/// (contain only valid npm name chars) mentioned alongside version-like tokens.
/// Returns any package name that appears 2+ times in different contexts.
pub(super) fn extract_conflicts_fallback(report: &str) -> HashSet<String> {
    let mut name_occurrences: HashMap<&str, usize> = HashMap::new();

    for line in report.lines() {
        let mut tokens = line.split_whitespace();
        let Some(mut prev) = tokens.next() else {
            continue;
        };
        for curr in tokens {
            let candidate = prev.trim_matches(|c: char| {
                !c.is_alphanumeric() && c != '@' && c != '/' && c != '.' && c != '-' && c != '_'
            });
            let next = curr.trim_matches(',');
            if !candidate.is_empty()
                && !candidate.starts_with('<')
                && !candidate.starts_with('>')
                && next.as_bytes().first().is_some_and(u8::is_ascii_digit)
                && candidate
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '@' | '/' | '.' | '-' | '_'))
            {
                *name_occurrences.entry(candidate).or_default() += 1;
            }
            prev = curr;
        }
    }

    name_occurrences
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// A registry refusing a metadata fetch for a reason that isn't the
/// package's absence: the credential, a rate limit, LPM Firewall, or the
/// registry's own refusal. It keeps its kind so the user is told to sign in,
/// wait, review the firewall report, or what the registry said, rather than
/// to change a version range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryFetchFailure {
    Http(Box<lpm_common::RegistryHttpError>),
    FirewallBlocked(Box<lpm_common::NpmFirewallBlockedErrorContext>),
    AuthRequired,
    SessionExpired,
    EnvTokenRejected,
    RateLimited { retry_after_secs: u64 },
}

impl RegistryFetchFailure {
    /// The failure a registry error is, or None for one that isn't a
    /// registry's refusal (a network error, an absent package).
    pub fn from_lpm_error(error: &lpm_common::LpmError) -> Option<Self> {
        use lpm_common::LpmError;
        match error {
            LpmError::RegistryHttp(answer) if answer.status != 404 => {
                Some(Self::Http(answer.clone()))
            }
            LpmError::NpmFirewallBlocked(blocked) => Some(Self::FirewallBlocked(blocked.clone())),
            LpmError::AuthRequired => Some(Self::AuthRequired),
            LpmError::SessionExpired => Some(Self::SessionExpired),
            LpmError::EnvTokenRejected => Some(Self::EnvTokenRejected),
            LpmError::RateLimited { retry_after_secs } => Some(Self::RateLimited {
                retry_after_secs: *retry_after_secs,
            }),
            _ => None,
        }
    }

    /// The error the CLI reports, naming the package the fetch was for.
    pub fn into_lpm_error(self, package: &str) -> lpm_common::LpmError {
        use lpm_common::LpmError;
        match self {
            Self::Http(answer) => {
                LpmError::RegistryHttp(Box::new(answer.with_subject(package.to_owned())))
            }
            Self::FirewallBlocked(blocked) => LpmError::NpmFirewallBlocked(blocked),
            Self::AuthRequired => LpmError::AuthRequired,
            Self::SessionExpired => LpmError::SessionExpired,
            Self::EnvTokenRejected => LpmError::EnvTokenRejected,
            Self::RateLimited { retry_after_secs } => LpmError::RateLimited { retry_after_secs },
        }
    }
}

impl std::fmt::Display for RegistryFetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(answer) => write!(f, "{answer}"),
            Self::FirewallBlocked(blocked) => write!(f, "{blocked}"),
            Self::AuthRequired => f.write_str("authentication required"),
            Self::SessionExpired => f.write_str("session expired or revoked"),
            Self::EnvTokenRejected => f.write_str("the registry rejected LPM_TOKEN"),
            Self::RateLimited { retry_after_secs } => {
                write!(f, "rate limited; retry after {retry_after_secs}s")
            }
        }
    }
}

/// Errors from the resolution process.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ResolveError {
    #[error("{0}")]
    Resolution(Box<ResolutionErrorContext>),

    #[error("{package}: {failure}")]
    Registry {
        package: String,
        failure: RegistryFetchFailure,
    },

    #[error("no solution found:\n{0}")]
    NoSolution(String),

    #[error("failed to fetch dependencies for {package}@{version}: {detail}")]
    DependencyFetch {
        package: String,
        version: String,
        detail: String,
    },

    #[error("package {package} was not found: {detail}")]
    PackageNotFound { package: String, detail: String },

    #[error("failed to choose version for {package}: {detail}")]
    VersionChoice { package: String, detail: String },

    #[error("resolution cancelled: {0}")]
    Cancelled(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error(
        "invalid required peer range {range:?} for {peer:?} declared by {package}@{version}: {detail}"
    )]
    InvalidPeerRange {
        package: String,
        version: String,
        peer: String,
        range: String,
        detail: String,
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
