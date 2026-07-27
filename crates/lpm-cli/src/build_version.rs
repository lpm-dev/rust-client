pub(crate) const VERSION: &str = match option_env!("LPM_BUILD_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[inline]
pub(crate) const fn version() -> &'static str {
    VERSION
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
}
