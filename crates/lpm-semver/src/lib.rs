//! npm-compatible semver parsing and matching for LPM.
//!
//! Wraps the `node-semver` crate with LPM-specific APIs.
//! This gives us npm-compatible behavior out of the box while allowing
//! us to extend or optimize internals later.
//!
//! # Examples
//!
//! ```
//! use lpm_semver::{Version, VersionReq};
//!
//! let version = Version::parse("1.2.3").unwrap();
//! let range = VersionReq::parse("^1.0.0").unwrap();
//! assert!(range.matches(&version));
//! ```

mod version;
mod version_req;

pub use version::Version;
pub use version_req::VersionReq;

/// Find the highest version from a list that satisfies a range.
///
/// Returns `None` if no version matches.
pub fn max_satisfying<'a>(versions: &[&'a Version], range: &VersionReq) -> Option<&'a Version> {
    versions
        .iter()
        .filter(|v| range.matches(v))
        .max_by(|a, b| a.cmp(b))
        .copied()
}

/// Sort versions in ascending order.
pub fn sort_versions(versions: &mut [Version]) {
    versions.sort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_satisfying_finds_highest_match() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("1.5.0").unwrap();
        let v3 = Version::parse("2.0.0").unwrap();
        let range = VersionReq::parse("^1.0.0").unwrap();

        let result = max_satisfying(&[&v1, &v2, &v3], &range);
        assert_eq!(result, Some(&v2));
    }

    #[test]
    fn max_satisfying_returns_none_when_no_match() {
        let v1 = Version::parse("2.0.0").unwrap();
        let range = VersionReq::parse("^1.0.0").unwrap();

        assert_eq!(max_satisfying(&[&v1], &range), None);
    }

    #[test]
    fn sort_versions_ascending() {
        let mut versions = vec![
            Version::parse("2.0.0").unwrap(),
            Version::parse("1.0.0").unwrap(),
            Version::parse("1.5.0").unwrap(),
        ];
        sort_versions(&mut versions);
        assert_eq!(versions[0].to_string(), "1.0.0");
        assert_eq!(versions[1].to_string(), "1.5.0");
        assert_eq!(versions[2].to_string(), "2.0.0");
    }
}
