use std::collections::HashSet;

use crate::package::CanonicalKey;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

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
    minimum_release_age_exclude: HashSet<CanonicalKey>,
    ignore_missing_release_time: bool,
    trust_policy: TrustPolicyMode,
}

impl Default for ResolverPolicy {
    fn default() -> Self {
        Self {
            minimum_release_age_secs: 0,
            cutoff_unix: None,
            minimum_release_age_exclude: HashSet::new(),
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
            std::iter::empty(),
        )
    }

    pub fn new_with_release_age_excludes(
        minimum_release_age_secs: u64,
        trust_policy: TrustPolicyMode,
        excludes: impl IntoIterator<Item = CanonicalKey>,
    ) -> Self {
        let cutoff_unix = if minimum_release_age_secs == 0 {
            None
        } else {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let min_age_secs = i64::try_from(minimum_release_age_secs).unwrap_or(i64::MAX);
            Some(now.saturating_sub(min_age_secs))
        };
        Self {
            minimum_release_age_secs,
            cutoff_unix,
            minimum_release_age_exclude: excludes.into_iter().collect(),
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
            minimum_release_age_exclude: excludes.into_iter().collect(),
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
    pub fn release_age_excluded(&self, package: &CanonicalKey) -> bool {
        self.minimum_release_age_exclude.contains(package)
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
        if self.release_age_excluded(package) {
            return ReleaseTimeStatus::Allowed;
        }
        self.release_time_status_inner(published_at)
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

    pub(crate) fn metadata_modified_after_cutoff_for_package(
        &self,
        package: &CanonicalKey,
        modified: Option<&str>,
    ) -> bool {
        if self.release_age_excluded(package) {
            return false;
        }
        self.metadata_modified_after_cutoff(modified)
    }

    pub(crate) fn metadata_modified_after_cutoff(&self, modified: Option<&str>) -> bool {
        let Some(cutoff_unix) = self.cutoff_unix else {
            return false;
        };
        let Some(modified) = modified else {
            return true;
        };
        parse_npm_time_unix(modified).is_none_or(|modified_unix| modified_unix > cutoff_unix)
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
    Provenance,
    TrustedPublisher,
    StagedPublish,
}

impl TrustEvidence {
    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Provenance => "provenance attestation",
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
