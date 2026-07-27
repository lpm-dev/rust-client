pub(crate) const VERSION: &str = match option_env!("LPM_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[inline]
pub(crate) const fn version() -> &'static str {
    VERSION
}

/// Version used to evaluate `package.json > engines.lpm`.
///
/// A nightly identifies the next development line, while the workspace
/// package version remains its stable compatibility baseline.
pub(crate) fn engine_compatibility_version() -> &'static str {
    engine_compatibility_version_for(VERSION, env!("CARGO_PKG_VERSION"))
}

fn engine_compatibility_version_for(
    build_version: &'static str,
    workspace_version: &'static str,
) -> &'static str {
    if crate::release_channel::ReleaseChannel::from_installed_version(build_version)
        == crate::release_channel::ReleaseChannel::Nightly
    {
        workspace_version
    } else {
        build_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_build_version_is_valid_semver() {
        assert!(
            lpm_semver::Version::parse(version()).is_ok(),
            "embedded build version must be valid semver: {}",
            version()
        );
    }

    #[test]
    fn nightly_build_uses_workspace_version_for_engine_compatibility() {
        assert_eq!(
            engine_compatibility_version_for("0.71.0-nightly.20260728.42.d82ceea", "0.70.0"),
            "0.70.0"
        );
    }

    #[test]
    fn stable_build_uses_embedded_version_for_engine_compatibility() {
        assert_eq!(
            engine_compatibility_version_for("0.71.0", "0.70.0"),
            "0.71.0"
        );
    }
}
