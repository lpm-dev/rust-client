use std::collections::HashSet;

use crate::npm_version::NpmVersion;
use crate::package::CanonicalKey;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReleaseAgeExclusion {
    Package(CanonicalKey),
    Version {
        package: CanonicalKey,
        version: NpmVersion,
    },
    Scope(String),
}

impl ReleaseAgeExclusion {
    pub fn matches(&self, package: &CanonicalKey, version: Option<&NpmVersion>) -> bool {
        match self {
            Self::Package(excluded) => excluded == package,
            Self::Version {
                package: excluded,
                version: excluded_version,
            } => excluded == package && version == Some(excluded_version),
            Self::Scope(prefix) => match package {
                CanonicalKey::Npm { name } => name.starts_with(prefix),
                CanonicalKey::Lpm { .. } => prefix == "@lpm.dev/",
                CanonicalKey::Root => false,
            },
        }
    }
}

impl From<CanonicalKey> for ReleaseAgeExclusion {
    fn from(package: CanonicalKey) -> Self {
        Self::Package(package)
    }
}

impl std::fmt::Display for ReleaseAgeExclusion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Package(package) => package.fmt(formatter),
            Self::Version { package, version } => write!(formatter, "{package}@{version}"),
            Self::Scope(prefix) => write!(formatter, "{prefix}*"),
        }
    }
}

impl std::str::FromStr for ReleaseAgeExclusion {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.is_empty() {
            return Err("entry is empty".to_string());
        }
        if raw.trim() != raw {
            return Err("entry has surrounding whitespace".to_string());
        }
        if raw.chars().any(char::is_whitespace) {
            return Err("entry contains whitespace".to_string());
        }
        if raw == "<root>" {
            return Err("the resolver root cannot be excluded".to_string());
        }
        if raw.contains(':') {
            return Err("protocol and package specifier forms are not supported".to_string());
        }
        if let Some(scope) = raw.strip_suffix("/*") {
            if valid_scope(scope) {
                return Ok(Self::Scope(format!("{scope}/")));
            }
            return Err("scoped wildcards must use the form `@scope/*`".to_string());
        }
        if raw
            .chars()
            .any(|character| matches!(character, '*' | '?' | '[' | ']'))
        {
            return Err("only the scoped wildcard form `@scope/*` is supported".to_string());
        }

        let version_separator = if raw.starts_with('@') {
            raw.find('/')
                .and_then(|slash| raw[slash + 1..].rfind('@').map(|at| slash + 1 + at))
        } else {
            raw.rfind('@')
        };
        if let Some(separator) = version_separator {
            let package = &raw[..separator];
            let version = &raw[separator + 1..];
            if !valid_package_name(package) {
                return Err("entry has an invalid package name".to_string());
            }
            let version = NpmVersion::parse(version)
                .map_err(|_| "version exclusions must use an exact semantic version".to_string())?;
            return Ok(Self::Version {
                package: CanonicalKey::from_dep_name(package),
                version,
            });
        }
        if !valid_package_name(raw) {
            return Err("entry has an invalid package name".to_string());
        }
        Ok(Self::Package(CanonicalKey::from_dep_name(raw)))
    }
}

fn valid_scope(scope: &str) -> bool {
    scope.starts_with('@')
        && scope.len() > 1
        && !scope[1..].contains(['/', '\\'])
        && !scope.contains("..")
        && scope.len() <= 214
}

fn valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 || name.contains('\0') || name.contains("..") {
        return false;
    }
    if name.starts_with('@') {
        let Some(slash_pos) = name.find('/') else {
            return false;
        };
        let scope = &name[..slash_pos];
        let package = &name[slash_pos + 1..];
        return valid_scope(scope)
            && !package.is_empty()
            && !package.contains('/')
            && !package.contains('\\');
    }
    !name.contains(['/', '\\', '@'])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustPolicyMode {
    #[default]
    Off,
    NoDowngrade,
}

impl TrustPolicyMode {
    #[inline]
    pub fn is_no_downgrade(self) -> bool {
        matches!(self, Self::NoDowngrade)
    }
}

#[derive(Debug, Clone)]
pub struct ResolverPolicy {
    minimum_release_age_secs: u64,
    cutoff_unix: Option<i64>,
    minimum_release_age_exclude: HashSet<ReleaseAgeExclusion>,
    minimum_release_age_packages: Option<HashSet<CanonicalKey>>,
    ignore_missing_release_time: bool,
    trust_policy: TrustPolicyMode,
}

impl Default for ResolverPolicy {
    fn default() -> Self {
        Self {
            minimum_release_age_secs: 0,
            cutoff_unix: None,
            minimum_release_age_exclude: HashSet::new(),
            minimum_release_age_packages: None,
            ignore_missing_release_time: true,
            trust_policy: TrustPolicyMode::Off,
        }
    }
}

impl ResolverPolicy {
    pub fn new(minimum_release_age_secs: u64, trust_policy: TrustPolicyMode) -> Self {
        Self::new_with_release_age_excludes(
            minimum_release_age_secs,
            trust_policy,
            std::iter::empty::<ReleaseAgeExclusion>(),
        )
    }

    pub fn new_with_release_age_excludes(
        minimum_release_age_secs: u64,
        trust_policy: TrustPolicyMode,
        excludes: impl IntoIterator<Item = ReleaseAgeExclusion>,
    ) -> Self {
        Self::new_inner(minimum_release_age_secs, trust_policy, excludes, None, None)
    }

    /// Builds a release-age policy evaluated against an explicit command
    /// timestamp so multiple importer resolutions share one cutoff.
    pub fn new_with_release_age_excludes_at_unix(
        minimum_release_age_secs: u64,
        trust_policy: TrustPolicyMode,
        excludes: impl IntoIterator<Item = ReleaseAgeExclusion>,
        now_unix: i64,
    ) -> Self {
        Self::new_inner(
            minimum_release_age_secs,
            trust_policy,
            excludes,
            None,
            Some(now_unix),
        )
    }

    pub fn new_with_release_age_excludes_and_packages(
        minimum_release_age_secs: u64,
        trust_policy: TrustPolicyMode,
        excludes: impl IntoIterator<Item = ReleaseAgeExclusion>,
        packages: impl IntoIterator<Item = CanonicalKey>,
    ) -> Self {
        Self::new_inner(
            minimum_release_age_secs,
            trust_policy,
            excludes,
            Some(packages.into_iter().collect()),
            None,
        )
    }

    /// Builds a direct-scope release-age policy evaluated against one explicit
    /// command timestamp.
    pub fn new_with_release_age_excludes_and_packages_at_unix(
        minimum_release_age_secs: u64,
        trust_policy: TrustPolicyMode,
        excludes: impl IntoIterator<Item = ReleaseAgeExclusion>,
        packages: impl IntoIterator<Item = CanonicalKey>,
        now_unix: i64,
    ) -> Self {
        Self::new_inner(
            minimum_release_age_secs,
            trust_policy,
            excludes,
            Some(packages.into_iter().collect()),
            Some(now_unix),
        )
    }

    fn new_inner(
        minimum_release_age_secs: u64,
        trust_policy: TrustPolicyMode,
        excludes: impl IntoIterator<Item = ReleaseAgeExclusion>,
        packages: Option<HashSet<CanonicalKey>>,
        now_unix: Option<i64>,
    ) -> Self {
        let cutoff_unix = if minimum_release_age_secs == 0 {
            None
        } else {
            let now = now_unix.unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());
            let min_age_secs = i64::try_from(minimum_release_age_secs).unwrap_or(i64::MAX);
            Some(now.saturating_sub(min_age_secs))
        };
        Self {
            minimum_release_age_secs,
            cutoff_unix,
            minimum_release_age_exclude: excludes.into_iter().collect(),
            minimum_release_age_packages: packages,
            ignore_missing_release_time: true,
            trust_policy,
        }
    }

    #[cfg(test)]
    pub fn with_cutoff_unix(
        minimum_release_age_secs: u64,
        cutoff_unix: i64,
        trust_policy: TrustPolicyMode,
    ) -> Self {
        Self {
            minimum_release_age_secs,
            cutoff_unix: (minimum_release_age_secs > 0).then_some(cutoff_unix),
            minimum_release_age_exclude: HashSet::new(),
            minimum_release_age_packages: None,
            ignore_missing_release_time: true,
            trust_policy,
        }
    }

    #[cfg(test)]
    pub fn with_cutoff_unix_and_release_age_packages(
        minimum_release_age_secs: u64,
        cutoff_unix: i64,
        trust_policy: TrustPolicyMode,
        packages: impl IntoIterator<Item = CanonicalKey>,
    ) -> Self {
        Self {
            minimum_release_age_secs,
            cutoff_unix: (minimum_release_age_secs > 0).then_some(cutoff_unix),
            minimum_release_age_exclude: HashSet::new(),
            minimum_release_age_packages: Some(packages.into_iter().collect()),
            ignore_missing_release_time: true,
            trust_policy,
        }
    }

    #[cfg(test)]
    pub fn with_cutoff_unix_and_release_age_excludes(
        minimum_release_age_secs: u64,
        cutoff_unix: i64,
        trust_policy: TrustPolicyMode,
        excludes: impl IntoIterator<Item = CanonicalKey>,
    ) -> Self {
        Self {
            minimum_release_age_secs,
            cutoff_unix: (minimum_release_age_secs > 0).then_some(cutoff_unix),
            minimum_release_age_exclude: excludes.into_iter().map(Into::into).collect(),
            minimum_release_age_packages: None,
            ignore_missing_release_time: true,
            trust_policy,
        }
    }

    #[inline]
    pub fn minimum_release_age_secs(&self) -> u64 {
        self.minimum_release_age_secs
    }

    #[inline]
    pub fn release_age_active(&self) -> bool {
        self.cutoff_unix.is_some()
    }

    #[inline]
    pub fn release_age_cutoff_unix(&self) -> Option<i64> {
        self.cutoff_unix
    }

    #[inline]
    pub fn release_age_excluded(&self, package: &CanonicalKey) -> bool {
        self.minimum_release_age_exclude
            .iter()
            .any(|exclude| exclude.matches(package, None))
    }

    #[inline]
    pub fn release_age_version_excluded(
        &self,
        package: &CanonicalKey,
        version: &NpmVersion,
    ) -> bool {
        self.minimum_release_age_exclude
            .iter()
            .any(|exclude| exclude.matches(package, Some(version)))
    }

    #[inline]
    pub fn release_age_applies_to_package(&self, package: &CanonicalKey) -> bool {
        self.cutoff_unix.is_some()
            && !self.release_age_excluded(package)
            && self
                .minimum_release_age_packages
                .as_ref()
                .is_none_or(|packages| packages.contains(package))
    }

    #[inline]
    pub fn release_age_checks_all_packages(&self) -> bool {
        self.cutoff_unix.is_some() && self.minimum_release_age_packages.is_none()
    }

    #[inline]
    pub fn trust_policy(&self) -> TrustPolicyMode {
        self.trust_policy
    }

    #[inline]
    pub fn requires_trust_history(&self) -> bool {
        self.trust_policy.is_no_downgrade()
    }

    pub fn release_time_status(&self, published_at: Option<&str>) -> ReleaseTimeStatus {
        self.release_time_status_inner(published_at)
    }

    pub fn release_time_status_for_package(
        &self,
        package: &CanonicalKey,
        published_at: Option<&str>,
    ) -> ReleaseTimeStatus {
        if !self.release_age_applies_to_package(package) {
            return ReleaseTimeStatus::Allowed;
        }
        self.release_time_status_inner(published_at)
    }

    pub fn release_time_status_for_package_version(
        &self,
        package: &CanonicalKey,
        version: &NpmVersion,
        published_at: Option<&str>,
    ) -> ReleaseTimeStatus {
        if self.release_age_version_excluded(package, version)
            || !self.release_age_applies_to_package(package)
        {
            return ReleaseTimeStatus::Allowed;
        }
        self.release_time_status_inner(published_at)
    }

    pub(crate) fn release_time_status_unix_for_package_version(
        &self,
        package: &CanonicalKey,
        version: &NpmVersion,
        published_unix: Option<i64>,
    ) -> ReleaseTimeStatus {
        if self.release_age_version_excluded(package, version)
            || !self.release_age_applies_to_package(package)
        {
            return ReleaseTimeStatus::Allowed;
        }
        self.release_time_status_unix_inner(published_unix)
    }

    fn release_time_status_inner(&self, published_at: Option<&str>) -> ReleaseTimeStatus {
        let Some(cutoff_unix) = self.cutoff_unix else {
            return ReleaseTimeStatus::Allowed;
        };
        let Some(published_at) = published_at else {
            return if self.ignore_missing_release_time {
                ReleaseTimeStatus::Allowed
            } else {
                ReleaseTimeStatus::Missing
            };
        };
        let Some(published_unix) = parse_npm_time_unix(published_at) else {
            return if self.ignore_missing_release_time {
                ReleaseTimeStatus::Allowed
            } else {
                ReleaseTimeStatus::Missing
            };
        };
        if published_unix <= cutoff_unix {
            ReleaseTimeStatus::Allowed
        } else {
            ReleaseTimeStatus::TooNew {
                remaining_secs: (published_unix - cutoff_unix) as u64,
            }
        }
    }

    fn release_time_status_unix_inner(&self, published_unix: Option<i64>) -> ReleaseTimeStatus {
        let Some(cutoff_unix) = self.cutoff_unix else {
            return ReleaseTimeStatus::Allowed;
        };
        let Some(published_unix) = published_unix else {
            return if self.ignore_missing_release_time {
                ReleaseTimeStatus::Allowed
            } else {
                ReleaseTimeStatus::Missing
            };
        };
        if published_unix <= cutoff_unix {
            ReleaseTimeStatus::Allowed
        } else {
            ReleaseTimeStatus::TooNew {
                remaining_secs: (published_unix - cutoff_unix) as u64,
            }
        }
    }

    pub(crate) fn metadata_modified_after_cutoff_for_package(
        &self,
        package: &CanonicalKey,
        modified: Option<&str>,
        modified_unix: Option<i64>,
    ) -> bool {
        if !self.release_age_applies_to_package(package) {
            return false;
        }
        self.metadata_modified_after_cutoff(modified, modified_unix)
    }

    pub(crate) fn metadata_modified_after_cutoff(
        &self,
        modified: Option<&str>,
        modified_unix: Option<i64>,
    ) -> bool {
        let Some(cutoff_unix) = self.cutoff_unix else {
            return false;
        };
        if modified.is_none() {
            return true;
        }
        modified_unix.is_none_or(|modified_unix| modified_unix > cutoff_unix)
    }

    pub(crate) fn metadata_modified_before_or_at_cutoff_for_package(
        &self,
        package: &CanonicalKey,
        modified: Option<&str>,
        modified_unix: Option<i64>,
    ) -> bool {
        if !self.release_age_applies_to_package(package) {
            return false;
        }
        let Some(cutoff_unix) = self.cutoff_unix else {
            return false;
        };
        if modified.is_none() {
            return false;
        }
        modified_unix.is_some_and(|modified_unix| modified_unix <= cutoff_unix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTimeStatus {
    Allowed,
    Missing,
    TooNew { remaining_secs: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustEvidence {
    TrustedPublisher,
    StagedPublish,
}

impl TrustEvidence {
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::TrustedPublisher => "trusted publisher",
            Self::StagedPublish => "staged publish approval",
        }
    }
}

pub(crate) fn parse_npm_time_unix(input: &str) -> Option<i64> {
    OffsetDateTime::parse(input, &Rfc3339)
        .ok()
        .map(|dt| dt.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_release_age_reference_produces_a_stable_cutoff() {
        let policy = ResolverPolicy::new_with_release_age_excludes_at_unix(
            600,
            TrustPolicyMode::Off,
            [],
            2_000,
        );

        assert_eq!(policy.release_age_cutoff_unix(), Some(1_400));
    }

    #[test]
    fn explicit_direct_scope_reference_keeps_package_selection_importer_local() {
        let included = CanonicalKey::npm("included");
        let policy = ResolverPolicy::new_with_release_age_excludes_and_packages_at_unix(
            600,
            TrustPolicyMode::Off,
            [],
            [included.clone()],
            2_000,
        );

        assert!(policy.release_age_applies_to_package(&included));
        assert!(!policy.release_age_applies_to_package(&CanonicalKey::npm("transitive")));
    }

    #[test]
    fn exact_version_exclusion_matches_only_its_package_release() {
        let exclusion: ReleaseAgeExclusion = "@scope/pkg@1.2.3"
            .parse()
            .expect("valid exact-version exclusion");
        let package = CanonicalKey::npm("@scope/pkg");
        let selected = NpmVersion::parse("1.2.3").expect("valid selected version");
        let other = NpmVersion::parse("1.2.4").expect("valid other version");

        assert!(exclusion.matches(&package, Some(&selected)));
        assert!(!exclusion.matches(&package, Some(&other)));
    }

    #[test]
    fn scoped_wildcard_exclusion_matches_packages_only_inside_the_scope() {
        let exclusion: ReleaseAgeExclusion =
            "@scope/*".parse().expect("valid scoped wildcard exclusion");

        assert!(exclusion.matches(&CanonicalKey::npm("@scope/pkg"), None));
        assert!(!exclusion.matches(&CanonicalKey::npm("@other/pkg"), None));
    }

    #[test]
    fn version_exclusion_rejects_a_range_selector() {
        let error = "pkg@^1.2.3"
            .parse::<ReleaseAgeExclusion>()
            .expect_err("release-age exclusions must identify one exact release");

        assert!(error.contains("exact semantic version"), "got: {error}");
    }
}
