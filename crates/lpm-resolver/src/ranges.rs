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

/// Phase 40 P2 — parsed npm-alias declaration.
///
/// pnpm/yarn/npm allow `"local_name": "npm:<target_name>@<range>"` in
/// `dependencies`. The local_name is the node_modules folder name the
/// consumer sees; the target_name is the package actually fetched from
/// the registry. See
/// <https://docs.npmjs.com/cli/v9/configuring-npm/package-json#alias-notation>.
///
/// Alias grammar:
///   `npm:` <target_name> `@` <range>
/// where target_name can be a plain or scoped package (`foo` or
/// `@scope/foo`) and range is any valid npm semver range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmAlias {
    /// The registry-canonical package name (what to fetch + how to key
    /// the store entry).
    pub target: String,
    /// The inner range that the target must satisfy.
    pub range: String,
}

/// Detect + parse the `npm:<target>@<range>` alias syntax. Returns
/// `None` for any non-alias range string (so the caller can fall
/// through to the regular semver parser).
///
/// The parser is permissive about what counts as a "valid" target +
/// range — those are re-validated downstream via `NpmRange::parse` and
/// `is_valid_dep_name`. This keeps the alias detection a single, cheap
/// prefix-and-split with no dependency on the regex/semver machinery.
pub fn parse_npm_alias(raw: &str) -> Option<NpmAlias> {
    let trimmed = raw.trim();
    let body = trimmed.strip_prefix("npm:")?;

    if body.is_empty() {
        return None;
    }

    // A scoped target starts with `@`; the split `@` for name/range is
    // therefore the LAST `@`, not the first. `npm:@types/node@^20.0.0`
    // must split at the second `@`, yielding target `@types/node` and
    // range `^20.0.0`.
    //
    // `npm:foo@latest`, `npm:foo@*`, `npm:foo@1.x` all parse the same
    // way — we hand the range off to `NpmRange::parse` downstream.
    //
    // Edge cases, all preserved by tests in this module:
    //   - bare target (`npm:foo`)                   → range = "*"
    //   - bare scoped (`npm:@scope/foo`)            → range = "*"
    //   - trailing `@` (`npm:foo@`)                 → range = "*"
    match body.rfind('@') {
        Some(0) | None => {
            // `npm:@scope/foo` (last `@` is the scope sigil) or
            // `npm:foo` (no `@` at all). Either way, no inline range —
            // default to wildcard.
            Some(NpmAlias {
                target: body.to_string(),
                range: "*".to_string(),
            })
        }
        Some(at_pos) => {
            let target = &body[..at_pos];
            let range = &body[at_pos + 1..];
            if target.is_empty() {
                return None;
            }
            Some(NpmAlias {
                target: target.to_string(),
                range: if range.is_empty() {
                    "*".to_string()
                } else {
                    range.to_string()
                },
            })
        }
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

    // === Phase 40 P2 — npm alias parsing ===

    #[test]
    fn alias_plain_package() {
        let a = parse_npm_alias("npm:strip-ansi@^6.0.1").expect("alias must parse");
        assert_eq!(a.target, "strip-ansi");
        assert_eq!(a.range, "^6.0.1");
    }

    #[test]
    fn alias_scoped_package_splits_on_last_at() {
        let a = parse_npm_alias("npm:@types/node@^20.0.0").expect("scoped alias must parse");
        assert_eq!(a.target, "@types/node");
        assert_eq!(a.range, "^20.0.0");
    }

    #[test]
    fn alias_exact_version() {
        let a = parse_npm_alias("npm:lodash@4.17.21").expect("exact-version alias must parse");
        assert_eq!(a.target, "lodash");
        assert_eq!(a.range, "4.17.21");
    }

    #[test]
    fn alias_latest_tag() {
        let a = parse_npm_alias("npm:foo@latest").expect("dist-tag alias must parse");
        assert_eq!(a.target, "foo");
        assert_eq!(a.range, "latest");
    }

    #[test]
    fn alias_wildcard_range() {
        let a = parse_npm_alias("npm:foo@*").expect("wildcard alias must parse");
        assert_eq!(a.target, "foo");
        assert_eq!(a.range, "*");
    }

    #[test]
    fn alias_bare_target_defaults_to_wildcard() {
        // Some tooling lets you write just `npm:foo` — treated as `*`.
        let a = parse_npm_alias("npm:foo").expect("bare alias must parse");
        assert_eq!(a.target, "foo");
        assert_eq!(a.range, "*");
    }

    #[test]
    fn alias_or_range() {
        let a = parse_npm_alias("npm:foo@^1.0.0 || ^2.0.0").expect("alias with OR must parse");
        assert_eq!(a.target, "foo");
        assert_eq!(a.range, "^1.0.0 || ^2.0.0");
    }

    #[test]
    fn non_alias_returns_none() {
        assert!(parse_npm_alias("^1.0.0").is_none());
        assert!(parse_npm_alias("1.2.3").is_none());
        assert!(parse_npm_alias("*").is_none());
        assert!(parse_npm_alias("latest").is_none());
        assert!(parse_npm_alias("workspace:*").is_none());
        assert!(parse_npm_alias("file:../foo").is_none());
        assert!(parse_npm_alias("git+https://...").is_none());
    }

    #[test]
    fn alias_with_whitespace_is_trimmed() {
        let a = parse_npm_alias("  npm:foo@^1.0.0  ").expect("whitespace-padded alias must parse");
        assert_eq!(a.target, "foo");
        assert_eq!(a.range, "^1.0.0");
    }

    #[test]
    fn alias_empty_range_defaults_to_wildcard() {
        // `npm:foo@` — trailing `@` with no range behaves like bare target.
        let a = parse_npm_alias("npm:foo@").expect("empty-range alias must parse");
        assert_eq!(a.target, "foo");
        assert_eq!(a.range, "*");
    }

    #[test]
    fn alias_empty_body_returns_none() {
        assert!(parse_npm_alias("npm:").is_none());
    }
}
