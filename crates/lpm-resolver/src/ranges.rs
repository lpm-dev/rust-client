//! Convert npm semver range syntax into PubGrub's `Ranges<NpmVersion>`.
//!
//! Strategy: We can't decompose node_semver::Range into intervals directly
//! (internal structure is private). Instead, we store the parsed range and
//! implement PubGrub's `VersionSet` trait using `Range::satisfies()`.
//!
//! This means our `NpmVersionSet` wraps `node_semver::Range` and delegates
//! all containment checks to it. For set operations (intersection, union, complement),
//! we compose the ranges using node_semver's built-in methods where possible,
//! and fall back to our own logic where needed.

use crate::npm_version::NpmVersion;
use std::fmt;
use version_ranges::Ranges;

/// An npm version range that can be used directly with known version lists.
///
/// Since PubGrub's `VersionSet` requires interval-based operations (complement,
/// intersection) that node_semver::Range doesn't expose cleanly, we use a
/// practical approach: when building `Ranges<NpmVersion>`, we filter a known
/// list of available versions through the npm range predicate.
///
/// This is called by the DependencyProvider when it knows the available versions.
#[derive(Clone, Debug)]
pub struct NpmRange {
    raw: String,
    parsed: node_semver::Range,
}

impl NpmRange {
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() || trimmed == "*" || trimmed == "latest" {
            return Ok(NpmRange {
                raw: "*".to_string(),
                parsed: node_semver::Range::any(),
            });
        }
        let parsed = node_semver::Range::parse(trimmed)
            .map_err(|e| format!("invalid range '{input}': {e}"))?;
        Ok(NpmRange {
            raw: trimmed.to_string(),
            parsed,
        })
    }

    /// Check if a version satisfies this range.
    pub fn satisfies(&self, version: &NpmVersion) -> bool {
        self.parsed.satisfies(version.as_inner())
    }

    /// Given a list of all available versions, return a `Ranges<NpmVersion>`
    /// that contains exactly the versions satisfying this npm range.
    ///
    /// This converts the predicate-based npm range into PubGrub's interval-based
    /// `Ranges` by building intervals around matching versions.
    pub fn to_pubgrub_ranges(&self, available_versions: &[NpmVersion]) -> Ranges<NpmVersion> {
        if self.raw == "*" {
            return Ranges::full();
        }

        let _span = tracing::debug_span!(
            "to_pubgrub_ranges",
            range = %self.raw,
            n_versions = available_versions.len(),
        )
        .entered();
        let _prof = crate::profile::to_pubgrub_ranges::start();

        // Phase 34.5: collect matching versions and build Ranges from sorted
        // singleton intervals in one pass. The old code did repeated
        // `union(&singleton)` which is O(n²) — each union scans the
        // accumulated interval list.
        //
        // available_versions is sorted descending (newest first). We reverse
        // to ascending for sorted interval construction. `Ranges::from_iter`
        // with pre-sorted non-overlapping intervals is O(n).
        use std::ops::Bound::Included;
        available_versions
            .iter()
            .rev()
            .filter(|v| self.satisfies(v))
            .map(|v| (Included(v.clone()), Included(v.clone())))
            .collect()
    }

    /// Create a `Ranges<NpmVersion>` using heuristic bounds (no available version list).
    ///
    /// This is less precise but works when we don't know the full version list yet.
    /// Used as a fallback — the exact approach with `to_pubgrub_ranges` is preferred.
    pub fn to_pubgrub_ranges_heuristic(&self) -> Ranges<NpmVersion> {
        if self.raw == "*" {
            return Ranges::full();
        }

        // Use min_version as a lower bound heuristic
        if let Some(min) = self.parsed.min_version() {
            // For caret ranges like ^1.2.3, the upper bound is < next major
            // For tilde ranges like ~1.2.3, the upper bound is < next minor
            // We use a broad range and rely on `satisfies` for exact filtering
            Ranges::higher_than(
                NpmVersion::parse(&min.to_string()).unwrap_or(NpmVersion::new(0, 0, 0)),
            )
        } else {
            Ranges::full()
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for NpmRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> NpmVersion {
        NpmVersion::parse(s).unwrap()
    }

    fn versions(strs: &[&str]) -> Vec<NpmVersion> {
        strs.iter().map(|s| v(s)).collect()
    }

    #[test]
    fn star_satisfies_all() {
        let r = NpmRange::parse("*").unwrap();
        assert!(r.satisfies(&v("0.0.1")));
        assert!(r.satisfies(&v("999.0.0")));
    }

    #[test]
    fn caret_range() {
        let r = NpmRange::parse("^1.2.3").unwrap();
        assert!(r.satisfies(&v("1.2.3")));
        assert!(r.satisfies(&v("1.9.9")));
        assert!(!r.satisfies(&v("2.0.0")));
        assert!(!r.satisfies(&v("1.2.2")));
    }

    #[test]
    fn tilde_range() {
        let r = NpmRange::parse("~1.2.3").unwrap();
        assert!(r.satisfies(&v("1.2.3")));
        assert!(r.satisfies(&v("1.2.9")));
        assert!(!r.satisfies(&v("1.3.0")));
    }

    #[test]
    fn or_range() {
        let r = NpmRange::parse("^1.0.0 || ^2.0.0").unwrap();
        assert!(r.satisfies(&v("1.5.0")));
        assert!(r.satisfies(&v("2.5.0")));
        assert!(!r.satisfies(&v("3.0.0")));
    }

    #[test]
    fn to_pubgrub_with_known_versions() {
        let r = NpmRange::parse("^1.0.0").unwrap();
        let avail = versions(&["0.9.0", "1.0.0", "1.5.0", "2.0.0"]);
        let ranges = r.to_pubgrub_ranges(&avail);

        assert!(ranges.contains(&v("1.0.0")));
        assert!(ranges.contains(&v("1.5.0")));
        assert!(!ranges.contains(&v("0.9.0")));
        assert!(!ranges.contains(&v("2.0.0")));
    }

    #[test]
    fn empty_is_wildcard() {
        let r = NpmRange::parse("").unwrap();
        assert!(r.satisfies(&v("1.0.0")));
    }

    #[test]
    fn latest_is_wildcard() {
        let r = NpmRange::parse("latest").unwrap();
        assert!(r.satisfies(&v("1.0.0")));
    }
}
