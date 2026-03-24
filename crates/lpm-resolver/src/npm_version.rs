//! npm-compatible version type for PubGrub.
//!
//! PubGrub's `Ranges<V>` needs `V: Ord + Clone + Display + Debug`.
//! We wrap `node_semver::Version` to satisfy these bounds while preserving
//! npm's ordering semantics (pre-release < release, build metadata ignored).

use std::cmp::Ordering;
use std::fmt;

/// Version type compatible with PubGrub's `Ranges<V>`.
///
/// Wraps a parsed semver version with npm-compatible ordering.
/// Two versions are equal if they have the same major.minor.patch and pre-release
/// (build metadata is ignored per semver spec).
#[derive(Clone, Debug, Eq)]
pub struct NpmVersion {
    inner: node_semver::Version,
}

impl NpmVersion {
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        NpmVersion {
            inner: node_semver::Version {
                major,
                minor,
                patch,
                pre_release: vec![],
                build: vec![],
            },
        }
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let inner = node_semver::Version::parse(input)
            .map_err(|e| format!("invalid version '{input}': {e}"))?;
        Ok(NpmVersion { inner })
    }

    pub fn major(&self) -> u64 {
        self.inner.major
    }

    pub fn minor(&self) -> u64 {
        self.inner.minor
    }

    pub fn patch(&self) -> u64 {
        self.inner.patch
    }

    pub fn is_prerelease(&self) -> bool {
        !self.inner.pre_release.is_empty()
    }

    /// Access inner for range matching.
    pub fn as_inner(&self) -> &node_semver::Version {
        &self.inner
    }
}

impl fmt::Display for NpmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl PartialEq for NpmVersion {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl PartialOrd for NpmVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NpmVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl std::hash::Hash for NpmVersion {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.major.hash(state);
        self.inner.minor.hash(state);
        self.inner.patch.hash(state);
        // Hash pre-release identifiers for consistency with Eq
        for id in &self.inner.pre_release {
            let s: String = id.to_string();
            s.hash(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        let v = NpmVersion::parse("1.2.3").unwrap();
        assert_eq!(v.to_string(), "1.2.3");
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 2);
        assert_eq!(v.patch(), 3);
    }

    #[test]
    fn ordering() {
        let v1 = NpmVersion::parse("1.0.0").unwrap();
        let v2 = NpmVersion::parse("1.0.1").unwrap();
        let v3 = NpmVersion::parse("2.0.0").unwrap();
        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn prerelease_less_than_release() {
        let pre = NpmVersion::parse("1.0.0-alpha").unwrap();
        let rel = NpmVersion::parse("1.0.0").unwrap();
        assert!(pre < rel);
    }

    #[test]
    fn equality_ignores_build() {
        let v1 = NpmVersion::parse("1.0.0+build1").unwrap();
        let v2 = NpmVersion::parse("1.0.0+build2").unwrap();
        // node_semver treats build metadata as irrelevant for comparison
        assert_eq!(v1, v2);
    }

    #[test]
    fn hash_consistency() {
        use std::collections::HashSet;
        let v1 = NpmVersion::parse("1.0.0").unwrap();
        let v2 = NpmVersion::parse("1.0.0").unwrap();
        let mut set = HashSet::new();
        set.insert(v1);
        assert!(set.contains(&v2));
    }
}
