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
    dist_tag: Option<String>,
}

impl NpmRange {
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() || trimmed == "*" {
            return Ok(NpmRange {
                raw: "*".to_string(),
                parsed: node_semver::Range::any(),
                dist_tag: None,
            });
        }
        if trimmed == "latest" {
            return Ok(NpmRange {
                raw: "latest".to_string(),
                parsed: node_semver::Range::any(),
                dist_tag: Some("latest".to_string()),
            });
        }
        let parsed = lpm_semver::parse_node_semver_range(trimmed)
            .map_err(|error| format!("invalid range '{input}': {error}"))?;
        Ok(NpmRange {
            raw: trimmed.to_string(),
            parsed,
            dist_tag: None,
        })
    }

    pub fn parse_registry_spec(input: &str) -> Result<Self, String> {
        match Self::parse(input) {
            Ok(range) => Ok(range),
            Err(_) if is_valid_dist_tag(input.trim()) => Ok(Self {
                raw: input.trim().to_string(),
                parsed: node_semver::Range::any(),
                dist_tag: Some(input.trim().to_string()),
            }),
            Err(error) => Err(error),
        }
    }

    /// Check if a version satisfies this range.
    pub fn satisfies(&self, version: &NpmVersion) -> bool {
        self.parsed.satisfies(version.as_inner())
    }

    pub fn satisfies_with_dist_tag(
        &self,
        version: &NpmVersion,
        tagged_version: Option<&NpmVersion>,
    ) -> bool {
        match self.dist_tag.as_deref() {
            None => self.satisfies(version),
            Some("latest") => {
                self.satisfies(version) && tagged_version.is_none_or(|latest| version <= latest)
            }
            Some(_) => tagged_version == Some(version),
        }
    }

    /// Given a list of all available versions, return a `Ranges<NpmVersion>`
    /// that contains exactly the versions satisfying this npm range.
    ///
    /// This converts the predicate-based npm range into PubGrub's interval-based
    /// `Ranges` by building intervals around matching versions.
    pub fn to_pubgrub_ranges(&self, available_versions: &[NpmVersion]) -> Ranges<NpmVersion> {
        self.to_pubgrub_ranges_with_dist_tag(available_versions, None)
    }

    pub fn to_pubgrub_ranges_with_dist_tag(
        &self,
        available_versions: &[NpmVersion],
        tagged_version: Option<&NpmVersion>,
    ) -> Ranges<NpmVersion> {
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

        // Collect matching versions and build Ranges from sorted singleton
        // intervals in one pass. The old code did repeated `union(&singleton)`
        // which is O(n²) — each union scans the accumulated interval list.
        //
        // available_versions is sorted descending (newest first). We reverse
        // to ascending for sorted interval construction. `Ranges::from_iter`
        // with pre-sorted non-overlapping intervals is O(n).
        use std::ops::Bound::Included;
        available_versions
            .iter()
            .rev()
            .filter(|version| self.satisfies_with_dist_tag(version, tagged_version))
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

    pub fn is_latest_tag(&self) -> bool {
        self.dist_tag.as_deref() == Some("latest")
    }

    pub fn dist_tag(&self) -> Option<&str> {
        self.dist_tag.as_deref()
    }

    pub fn exact_version(&self) -> Option<NpmVersion> {
        if self.dist_tag.is_some() {
            return None;
        }
        let raw = self.raw.strip_prefix('=').unwrap_or(&self.raw);
        NpmVersion::parse(raw).ok()
    }
}

fn is_valid_dist_tag(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
                )
        })
}

/// Parsed npm-alias declaration.
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

/// **R3 / B2 defense-in-depth.** True when `range_str` is a
/// `workspace:` specifier. The `workspace:` protocol is a manifest-
/// level opt-in for "this dep lives in the workspace, not the
/// registry"; resolution happens upstream in [`crate::specifier`] +
/// `lpm-workspace` which rewrite such deps before either resolver arm
/// runs. If a raw `workspace:<rest>` reaches the resolver — through a
/// future refactor that drops the upstream layer, a hand-edited
/// manifest, or a malformed cache entry — the caller deserves a
/// specific diagnostic rather than the opaque semver-parse failure
/// that `NpmRange::parse("workspace:*")` would otherwise produce.
///
/// Lifted to `crate::ranges` so both resolver arms (greedy/fused +
/// pubgrub) consult the same predicate.
pub fn is_workspace_specifier(range_str: &str) -> bool {
    range_str.trim_start().starts_with("workspace:")
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
    fn latest_matches_any_version_without_a_tag_target() {
        let r = NpmRange::parse("latest").unwrap();
        assert!(r.satisfies(&v("1.0.0")));
        assert_eq!(r.raw(), "latest");
    }

    #[test]
    fn latest_bound_excludes_semver_greater_versions() {
        let r = NpmRange::parse("latest").unwrap();
        let avail = versions(&["3.0.0", "3.1.0", "4.0.0"]);
        let latest = v("3.1.0");
        let ranges = r.to_pubgrub_ranges_with_dist_tag(&avail, Some(&latest));

        assert!(ranges.contains(&v("3.0.0")));
        assert!(ranges.contains(&v("3.1.0")));
        assert!(!ranges.contains(&v("4.0.0")));
    }

    #[test]
    fn custom_dist_tag_is_only_accepted_as_a_registry_spec() {
        assert!(NpmRange::parse("legacy").is_err());
        let range = NpmRange::parse_registry_spec("legacy").expect("valid custom dist-tag");
        let tagged = v("1.2.3");

        assert_eq!(range.dist_tag(), Some("legacy"));
        assert!(range.satisfies_with_dist_tag(&tagged, Some(&tagged)));
        assert!(!range.satisfies_with_dist_tag(&v("2.0.0"), Some(&tagged)));
    }

    #[test]
    fn registry_spec_rejects_non_url_safe_malformed_range() {
        assert!(NpmRange::parse_registry_spec("~X0^.00").is_err());
    }

    #[test]
    fn malformed_wildcard_range_returns_error() {
        assert!(NpmRange::parse("=xx").is_err());
        assert!(NpmRange::parse("^1.0.0 ||=*3").is_err());
        assert!(NpmRange::parse("~X0^.00").is_err());
    }

    #[test]
    fn wildcard_range_operators_are_valid_in_compound_ranges() {
        let or_with_caret_wildcard = NpmRange::parse("^x || ^1.0.0").unwrap();
        assert!(or_with_caret_wildcard.satisfies(&v("0.0.9")));
        assert!(or_with_caret_wildcard.satisfies(&v("4.2.0")));

        let compound_with_wildcard_identity = NpmRange::parse(">=1.0.0 ~x").unwrap();
        assert!(!compound_with_wildcard_identity.satisfies(&v("0.9.9")));
        assert!(compound_with_wildcard_identity.satisfies(&v("1.0.0")));
        assert!(compound_with_wildcard_identity.satisfies(&v("4.2.0")));
    }

    // === npm alias parsing ===

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
