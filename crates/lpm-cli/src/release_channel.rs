use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ReleaseChannel {
    Stable,
    Nightly,
}

impl ReleaseChannel {
    #[inline]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Nightly => "nightly",
        }
    }

    pub(crate) fn from_installed_version(version: &str) -> Self {
        let Ok(version) = lpm_semver::Version::parse(version) else {
            return Self::Stable;
        };
        if version
            .pre_release()
            .first()
            .is_some_and(|id| id == "nightly")
        {
            Self::Nightly
        } else {
            Self::Stable
        }
    }

    pub(crate) fn accepts_version(self, version: &str) -> bool {
        let Ok(version) = lpm_semver::Version::parse(version) else {
            return false;
        };
        match self {
            Self::Stable => !version.is_prerelease(),
            Self::Nightly => version
                .pre_release()
                .first()
                .is_some_and(|id| id == "nightly"),
        }
    }
}

impl std::fmt::Display for ReleaseChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_nightly_version_selects_nightly_channel() {
        assert_eq!(
            ReleaseChannel::from_installed_version("0.71.0-nightly.20260728.4567.d82ceea"),
            ReleaseChannel::Nightly
        );
    }

    #[test]
    fn installed_stable_version_selects_stable_channel() {
        assert_eq!(
            ReleaseChannel::from_installed_version("0.71.0"),
            ReleaseChannel::Stable
        );
    }

    #[test]
    fn stable_channel_rejects_prerelease_version() {
        assert!(!ReleaseChannel::Stable.accepts_version("0.71.0-nightly.20260728.4567.d82ceea"));
    }

    #[test]
    fn nightly_channel_rejects_stable_version() {
        assert!(!ReleaseChannel::Nightly.accepts_version("0.71.0"));
    }

    #[test]
    fn nightly_channel_rejects_other_prerelease_kinds() {
        assert!(!ReleaseChannel::Nightly.accepts_version("0.71.0-rc.1"));
    }

    #[test]
    fn channels_reject_malformed_versions() {
        assert!(!ReleaseChannel::Stable.accepts_version("not-semver"));
        assert!(!ReleaseChannel::Nightly.accepts_version("not-semver"));
    }
}
