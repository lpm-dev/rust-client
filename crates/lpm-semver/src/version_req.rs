use crate::version::Version;
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A version requirement (range) that versions can be matched against.
///
/// Supports the full npm range syntax:
/// - Exact: `1.2.3`
/// - Caret: `^1.2.3` (compatible with version)
/// - Tilde: `~1.2.3` (patch-level changes)
/// - Comparison: `>=1.0.0`, `<2.0.0`, `>=1.0.0 <2.0.0`
/// - OR: `^1.0.0 || ^2.0.0`
/// - Wildcard: `*`, `1.x`, `1.2.x`
/// - Hyphen ranges: `1.0.0 - 2.0.0`
///
/// Internally delegates to `node_semver::Range` for npm-compatible behavior.
#[derive(Debug, Clone)]
pub struct VersionReq {
    inner: node_semver::Range,
    /// Original string for display (node_semver normalizes the range on parse).
    original: String,
}

impl VersionReq {
    /// Parse a version range string.
    ///
    /// # Examples
    /// ```
    /// use lpm_semver::VersionReq;
    ///
    /// let range = VersionReq::parse("^1.0.0").unwrap();
    /// let range = VersionReq::parse(">=1.0.0 <2.0.0").unwrap();
    /// let range = VersionReq::parse("^1.0.0 || ^2.0.0").unwrap();
    /// let range = VersionReq::parse("*").unwrap();
    /// ```
    pub fn parse(input: &str) -> Result<Self, LpmError> {
        let inner = node_semver::Range::parse(input)
            .map_err(|e| LpmError::InvalidVersionRange(format!("{input}: {e}")))?;
        Ok(VersionReq {
            inner,
            original: input.to_string(),
        })
    }

    /// Check if a version satisfies this range.
    pub fn matches(&self, version: &Version) -> bool {
        self.inner.satisfies(version.as_inner())
    }

    /// Returns the original range string as provided to parse().
    pub fn original(&self) -> &str {
        &self.original
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

impl PartialEq for VersionReq {
    fn eq(&self, other: &Self) -> bool {
        // Compare the normalized internal representation
        self.inner.to_string() == other.inner.to_string()
    }
}

impl Eq for VersionReq {}

impl Serialize for VersionReq {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.original)
    }
}

impl<'de> Deserialize<'de> for VersionReq {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        VersionReq::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn r(s: &str) -> VersionReq {
        VersionReq::parse(s).unwrap()
    }

    // --- Caret ranges (^) ---
    // ^1.2.3 := >=1.2.3 <2.0.0
    // ^0.2.3 := >=0.2.3 <0.3.0
    // ^0.0.3 := >=0.0.3 <0.0.4

    #[test]
    fn caret_major() {
        let range = r("^1.2.3");
        assert!(range.matches(&v("1.2.3")));
        assert!(range.matches(&v("1.9.9")));
        assert!(!range.matches(&v("2.0.0")));
        assert!(!range.matches(&v("1.2.2")));
    }

    #[test]
    fn caret_minor_zero() {
        let range = r("^0.2.3");
        assert!(range.matches(&v("0.2.3")));
        assert!(range.matches(&v("0.2.9")));
        assert!(!range.matches(&v("0.3.0")));
    }

    #[test]
    fn caret_patch_zero() {
        let range = r("^0.0.3");
        assert!(range.matches(&v("0.0.3")));
        assert!(!range.matches(&v("0.0.4")));
    }

    // --- Tilde ranges (~) ---
    // ~1.2.3 := >=1.2.3 <1.3.0
    // ~0.2.3 := >=0.2.3 <0.3.0

    #[test]
    fn tilde_range() {
        let range = r("~1.2.3");
        assert!(range.matches(&v("1.2.3")));
        assert!(range.matches(&v("1.2.9")));
        assert!(!range.matches(&v("1.3.0")));
    }

    // --- Comparison operators ---

    #[test]
    fn gte_range() {
        let range = r(">=1.0.0");
        assert!(range.matches(&v("1.0.0")));
        assert!(range.matches(&v("2.0.0")));
        assert!(!range.matches(&v("0.9.9")));
    }

    #[test]
    fn compound_range() {
        let range = r(">=1.0.0 <2.0.0");
        assert!(range.matches(&v("1.0.0")));
        assert!(range.matches(&v("1.9.9")));
        assert!(!range.matches(&v("2.0.0")));
        assert!(!range.matches(&v("0.9.9")));
    }

    // --- OR ranges (||) ---

    #[test]
    fn or_range() {
        let range = r("^1.0.0 || ^2.0.0");
        assert!(range.matches(&v("1.5.0")));
        assert!(range.matches(&v("2.5.0")));
        assert!(!range.matches(&v("3.0.0")));
    }

    // --- Wildcard ranges ---

    #[test]
    fn star_matches_everything() {
        let range = r("*");
        assert!(range.matches(&v("0.0.1")));
        assert!(range.matches(&v("999.999.999")));
    }

    #[test]
    fn x_range_minor() {
        let range = r("1.x");
        assert!(range.matches(&v("1.0.0")));
        assert!(range.matches(&v("1.9.9")));
        assert!(!range.matches(&v("2.0.0")));
    }

    #[test]
    fn x_range_patch() {
        let range = r("1.2.x");
        assert!(range.matches(&v("1.2.0")));
        assert!(range.matches(&v("1.2.9")));
        assert!(!range.matches(&v("1.3.0")));
    }

    // --- Exact version ---

    #[test]
    fn exact_version() {
        let range = r("1.2.3");
        assert!(range.matches(&v("1.2.3")));
        assert!(!range.matches(&v("1.2.4")));
    }

    // --- Pre-release handling ---

    #[test]
    fn prerelease_only_matches_same_major_minor_patch() {
        // npm semver rule: pre-releases only match ranges that explicitly
        // include a pre-release on the same [major, minor, patch] tuple
        let range = r(">=1.0.0-alpha <1.0.0");
        assert!(range.matches(&v("1.0.0-beta")));
        assert!(!range.matches(&v("1.0.1-alpha")));
    }

    // --- Hyphen range ---

    #[test]
    fn hyphen_range() {
        let range = r("1.0.0 - 2.0.0");
        assert!(range.matches(&v("1.0.0")));
        assert!(range.matches(&v("1.5.0")));
        assert!(range.matches(&v("2.0.0")));
        assert!(!range.matches(&v("2.0.1")));
        assert!(!range.matches(&v("0.9.9")));
    }

    // --- Edge cases ---

    #[test]
    fn empty_string_rejected() {
        // node-semver crate rejects empty strings (npm CLI treats as "*").
        // This is acceptable — real package.json never has empty version ranges.
        assert!(VersionReq::parse("").is_err());
    }

    #[test]
    fn reject_invalid_range() {
        assert!(VersionReq::parse("not a range at all!!!").is_err());
    }

    // --- Display ---

    #[test]
    fn display_preserves_original() {
        let range = r("^1.0.0 || ^2.0.0");
        assert_eq!(range.to_string(), "^1.0.0 || ^2.0.0");
    }

    // --- Serde ---

    #[test]
    fn serde_roundtrip() {
        let range = r("^1.0.0");
        let json = serde_json::to_string(&range).unwrap();
        let parsed: VersionReq = serde_json::from_str(&json).unwrap();
        assert_eq!(range.original(), parsed.original());
    }
}
