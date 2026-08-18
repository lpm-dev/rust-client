use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// npm-compatible version increment target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionBump {
    Patch,
    Minor,
    Major,
    PrePatch,
    PreMinor,
    PreMajor,
    Prerelease,
    Exact(String),
}

impl VersionBump {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
            Self::PrePatch => "prepatch",
            Self::PreMinor => "preminor",
            Self::PreMajor => "premajor",
            Self::Prerelease => "prerelease",
            Self::Exact(version) => version,
        }
    }
}

impl FromStr for VersionBump {
    type Err = LpmError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(match input {
            "patch" => Self::Patch,
            "minor" => Self::Minor,
            "major" => Self::Major,
            "prepatch" => Self::PrePatch,
            "preminor" => Self::PreMinor,
            "premajor" => Self::PreMajor,
            "prerelease" => Self::Prerelease,
            exact => {
                Version::parse(exact)?;
                Self::Exact(exact.to_string())
            }
        })
    }
}

/// A parsed semantic version.
///
/// Supports the full semver 2.0.0 spec plus npm extensions:
/// - Pre-release: `1.0.0-alpha.1`
/// - Build metadata: `1.0.0+build.456`
///
/// Internally delegates to `node_semver::Version` for npm-compatible parsing.
#[derive(Debug, Clone, Eq)]
pub struct Version {
    inner: node_semver::Version,
}

impl Version {
    /// Parse a version string.
    ///
    /// Accepts standard semver (`1.2.3`) and npm's optional `v` prefix (`v1.2.3`).
    /// Partial versions such as `1.2` are ranges, not exact versions, and are rejected.
    pub fn parse(input: &str) -> Result<Self, LpmError> {
        let inner = node_semver::Version::parse(input)
            .map_err(|e| LpmError::InvalidVersion(format!("{input}: {e}")))?;
        Ok(Version { inner })
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

    /// Returns the pre-release identifiers, if any.
    /// e.g., `1.0.0-beta.1` → `["beta", "1"]`
    pub fn pre_release(&self) -> Vec<String> {
        self.inner
            .pre_release
            .iter()
            .map(|id| id.to_string())
            .collect()
    }

    /// Returns the build metadata, if any.
    /// e.g., `1.0.0+build.456` → `["build", "456"]`
    pub fn build_metadata(&self) -> Vec<String> {
        self.inner.build.iter().map(|id| id.to_string()).collect()
    }

    /// Whether this is a pre-release version (has pre-release identifiers).
    pub fn is_prerelease(&self) -> bool {
        !self.inner.pre_release.is_empty()
    }

    /// Access the underlying node_semver::Version for interop.
    pub fn as_inner(&self) -> &node_semver::Version {
        &self.inner
    }

    /// Increment this version using npm's `npm version` semantics.
    pub fn bump(&self, bump: &VersionBump) -> Result<Self, LpmError> {
        match bump {
            VersionBump::Patch => {
                if self.is_prerelease() {
                    Version::parse(&format!(
                        "{}.{}.{}",
                        self.major(),
                        self.minor(),
                        self.patch()
                    ))
                } else {
                    Version::parse(&format!(
                        "{}.{}.{}",
                        self.major(),
                        self.minor(),
                        self.patch() + 1
                    ))
                }
            }
            VersionBump::Minor => {
                if self.is_prerelease() && self.patch() == 0 {
                    Version::parse(&format!("{}.{}.0", self.major(), self.minor()))
                } else {
                    Version::parse(&format!("{}.{}.0", self.major(), self.minor() + 1))
                }
            }
            VersionBump::Major => {
                if self.is_prerelease() && self.minor() == 0 && self.patch() == 0 {
                    Version::parse(&format!("{}.0.0", self.major()))
                } else {
                    Version::parse(&format!("{}.0.0", self.major() + 1))
                }
            }
            VersionBump::PrePatch => Version::parse(&format!(
                "{}.{}.{}-0",
                self.major(),
                self.minor(),
                self.patch() + 1
            )),
            VersionBump::PreMinor => {
                Version::parse(&format!("{}.{}.0-0", self.major(), self.minor() + 1))
            }
            VersionBump::PreMajor => Version::parse(&format!("{}.0.0-0", self.major() + 1)),
            VersionBump::Prerelease => {
                if self.is_prerelease() {
                    let pre = increment_prerelease(self.pre_release());
                    Version::parse(&format!(
                        "{}.{}.{}-{}",
                        self.major(),
                        self.minor(),
                        self.patch(),
                        pre.join(".")
                    ))
                } else {
                    Version::parse(&format!(
                        "{}.{}.{}-0",
                        self.major(),
                        self.minor(),
                        self.patch() + 1
                    ))
                }
            }
            VersionBump::Exact(version) => Version::parse(version),
        }
    }
}

fn increment_prerelease(mut identifiers: Vec<String>) -> Vec<String> {
    if let Some(last) = identifiers.last_mut()
        && let Ok(number) = last.parse::<u64>()
    {
        *last = (number + 1).to_string();
        return identifiers;
    }
    identifiers.push("0".to_string());
    identifiers
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Version::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_version() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 2);
        assert_eq!(v.patch(), 3);
        assert!(!v.is_prerelease());
    }

    #[test]
    fn parse_prerelease() {
        let v = Version::parse("1.0.0-beta.1").unwrap();
        assert!(v.is_prerelease());
        assert_eq!(v.pre_release(), vec!["beta", "1"]);
    }

    #[test]
    fn parse_build_metadata() {
        let v = Version::parse("1.0.0+build.456").unwrap();
        assert_eq!(v.build_metadata(), vec!["build", "456"]);
        assert!(!v.is_prerelease());
    }

    #[test]
    fn parse_prerelease_and_build() {
        let v = Version::parse("1.0.0-alpha.1+build.123").unwrap();
        assert!(v.is_prerelease());
        assert_eq!(v.pre_release(), vec!["alpha", "1"]);
        assert_eq!(v.build_metadata(), vec!["build", "123"]);
    }

    #[test]
    fn version_comparison() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("1.0.1").unwrap();
        let v3 = Version::parse("2.0.0").unwrap();

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn prerelease_is_less_than_release() {
        let pre = Version::parse("1.0.0-alpha").unwrap();
        let release = Version::parse("1.0.0").unwrap();
        assert!(pre < release);
    }

    #[test]
    fn version_equality() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("1.0.0").unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn display_format() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn reject_invalid_version() {
        assert!(Version::parse("not-a-version").is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let v = Version::parse("1.2.3-beta.1").unwrap();
        let json = serde_json::to_string(&v).unwrap();
        let parsed: Version = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn bump_patch_releases_existing_prerelease() {
        let v = Version::parse("1.2.3-alpha.7").unwrap();
        assert_eq!(v.bump(&VersionBump::Patch).unwrap().to_string(), "1.2.3");
    }

    #[test]
    fn bump_prerelease_starts_next_patch_for_stable_version() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(
            v.bump(&VersionBump::Prerelease).unwrap().to_string(),
            "1.2.4-0"
        );
    }

    #[test]
    fn bump_prerelease_increments_numeric_identifier() {
        let v = Version::parse("1.2.3-alpha.7").unwrap();
        assert_eq!(
            v.bump(&VersionBump::Prerelease).unwrap().to_string(),
            "1.2.3-alpha.8"
        );
    }

    #[test]
    fn bump_prerelease_appends_numeric_identifier_when_missing() {
        let v = Version::parse("1.2.3-alpha.beta").unwrap();
        assert_eq!(
            v.bump(&VersionBump::Prerelease).unwrap().to_string(),
            "1.2.3-alpha.beta.0"
        );
    }

    #[test]
    fn bump_preminor_uses_numeric_prerelease_default() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(
            v.bump(&VersionBump::PreMinor).unwrap().to_string(),
            "1.3.0-0"
        );
    }

    #[test]
    fn bump_minor_releases_existing_minor_boundary_prerelease() {
        let v = Version::parse("1.3.0-0").unwrap();
        assert_eq!(v.bump(&VersionBump::Minor).unwrap().to_string(), "1.3.0");
    }

    #[test]
    fn bump_major_releases_existing_major_boundary_prerelease() {
        let v = Version::parse("2.0.0-0").unwrap();
        assert_eq!(v.bump(&VersionBump::Major).unwrap().to_string(), "2.0.0");
    }
}
