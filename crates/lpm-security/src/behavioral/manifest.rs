//! Package manifest (package.json) tag detection (6 tags).
//!
//! Analyzes package.json fields for security-relevant signals without
//! scanning source files. These checks detect dependency configuration
//! risks and license compliance issues.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Manifest-level tags derived from package.json analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ManifestTags {
    pub git_dependency: bool,
    pub http_dependency: bool,
    pub wildcard_dependency: bool,
    pub copyleft_license: bool,
    pub no_license: bool,
    /// `SEE LICENSE IN <file>`: the package ships its own license terms
    /// instead of an SPDX expression.
    pub custom_license: bool,
}

/// Known copyleft license identifiers (case-insensitive matching).
/// Covers SPDX identifiers and common variations.
const COPYLEFT_IDENTIFIERS: &[&str] = &[
    "gpl",
    "agpl",
    "lgpl",
    "mpl",
    "eupl",
    "sspl",
    "cpal",
    "osl",
    "cc-by-sa",
    "artistic-2.0",
    "cecill",
    "ofl",
    "sleepycat",
    "watcom",
    "rpsl",
    "rpl",
    "ms-rl",
    "reciprocal",
];

/// Analyze a parsed package.json for manifest tags.
///
/// Takes individual fields rather than a full struct to avoid coupling
/// to a specific package.json parser.
pub fn analyze_manifest(
    license: Option<&str>,
    dependencies: Option<&HashMap<String, String>>,
    dev_dependencies: Option<&HashMap<String, String>>,
    optional_dependencies: Option<&HashMap<String, String>>,
) -> ManifestTags {
    analyze_manifest_with_privacy(
        license,
        false,
        dependencies,
        dev_dependencies,
        optional_dependencies,
    )
}

pub fn analyze_manifest_with_privacy(
    license: Option<&str>,
    private_package: bool,
    dependencies: Option<&HashMap<String, String>>,
    dev_dependencies: Option<&HashMap<String, String>>,
    optional_dependencies: Option<&HashMap<String, String>>,
) -> ManifestTags {
    let mut tags = ManifestTags::default();

    // ── License checks ────────────────────────────────────────

    let lower = license.map(|lic| lic.trim().to_lowercase());
    match lower.as_deref() {
        None | Some("" | "unlicensed" | "none" | "proprietary") => {
            tags.no_license = !private_package;
        }
        Some(lic) if lic.starts_with("see license in") => {
            tags.custom_license = !private_package;
        }
        Some(lic) => {
            tags.copyleft_license = license_expression_is_copyleft_lower(lic);
        }
    }

    // ── Dependency checks ─────────────────────────────────────

    let all_deps = [dependencies, dev_dependencies, optional_dependencies];

    for deps in all_deps.into_iter().flatten() {
        for version in deps.values() {
            let v = version.trim();

            // Git dependencies
            if v.starts_with("git://")
                || v.starts_with("git+ssh://")
                || v.starts_with("git+https://")
                || v.starts_with("git+http://")
                || v.starts_with("github:")
                || v.starts_with("bitbucket:")
                || v.starts_with("gitlab:")
            {
                tags.git_dependency = true;
            }

            if is_repo_shorthand(v) {
                tags.git_dependency = true;
            }

            // HTTP dependencies (insecure transport)
            if v.starts_with("http://") {
                tags.http_dependency = true;
            }

            // Wildcard dependencies
            if v == "*" || v.is_empty() || v == "latest" {
                tags.wildcard_dependency = true;
            }
        }
    }

    tags
}

/// `owner/repo` shorthand, optionally with `#ref`, which npm installs from
/// GitHub. A colon before the first slash marks a protocol (`jsr:`, `file:`,
/// `portal:`, …) instead.
fn is_repo_shorthand(spec: &str) -> bool {
    const NOT_SHORTHAND_PREFIXES: [&str; 8] = ["http", "git", "@", ">", "<", "=", "^", "~"];
    let Some(slash) = spec.find('/') else {
        return false;
    };
    slash > 0
        && !spec[..slash].contains(':')
        && !NOT_SHORTHAND_PREFIXES
            .iter()
            .any(|prefix| spec.starts_with(prefix))
}

/// Check if a license SPDX expression contains a copyleft identifier.
///
/// Handles compound expressions: "MIT OR GPL-3.0" → copyleft present.
/// Case-insensitive. Scans for any copyleft identifier as a substring
/// within the SPDX tokens.
pub fn license_expression_is_copyleft(license: &str) -> bool {
    let license_lower = license.to_lowercase();
    license_expression_is_copyleft_lower(&license_lower)
}

fn license_expression_is_copyleft_lower(license_lower: &str) -> bool {
    // Split on SPDX operators to get individual license identifiers
    // Operators: OR, AND, WITH (case-insensitive, already lowered)
    let tokens: Vec<&str> = license_lower
        .split(['(', ')', ' '])
        .filter(|t| !t.is_empty() && *t != "or" && *t != "and" && *t != "with")
        .collect();

    for token in tokens {
        for copyleft in COPYLEFT_IDENTIFIERS {
            if token.contains(copyleft) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deps(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ── License: no license ───────────────────────────────────

    #[test]
    fn no_license_missing() {
        let tags = analyze_manifest(None, None, None, None);
        assert!(tags.no_license);
        assert!(!tags.copyleft_license);
    }

    #[test]
    fn no_license_private_package_is_ignored() {
        let tags = analyze_manifest_with_privacy(None, true, None, None, None);
        assert!(!tags.no_license);
        assert!(!tags.copyleft_license);
    }

    #[test]
    fn no_license_empty() {
        let tags = analyze_manifest(Some(""), None, None, None);
        assert!(tags.no_license);
    }

    #[test]
    fn no_license_unlicensed() {
        let tags = analyze_manifest(Some("UNLICENSED"), None, None, None);
        assert!(tags.no_license);
    }

    #[test]
    fn no_license_blank() {
        let tags = analyze_manifest(Some("   "), None, None, None);
        assert!(tags.no_license);
        assert!(!tags.custom_license);
    }

    #[test]
    fn no_license_none() {
        let tags = analyze_manifest(Some("None"), None, None, None);
        assert!(tags.no_license);
    }

    #[test]
    fn no_license_proprietary() {
        let tags = analyze_manifest(Some("proprietary"), None, None, None);
        assert!(tags.no_license);
    }

    // ── License: custom terms ─────────────────────────────────

    #[test]
    fn custom_license_see_license_in() {
        let tags = analyze_manifest(Some("SEE LICENSE IN LICENSE.md"), None, None, None);
        assert!(tags.custom_license);
        assert!(!tags.no_license);
        assert!(!tags.copyleft_license);
    }

    #[test]
    fn custom_license_is_case_and_whitespace_insensitive() {
        let tags = analyze_manifest(Some("  see license in EULA.txt "), None, None, None);
        assert!(tags.custom_license);
        assert!(!tags.no_license);
    }

    #[test]
    fn custom_license_private_package_is_ignored() {
        let tags =
            analyze_manifest_with_privacy(Some("SEE LICENSE IN LICENSE"), true, None, None, None);
        assert!(!tags.custom_license);
        assert!(!tags.no_license);
    }

    #[test]
    fn custom_license_file_name_is_not_read_as_copyleft() {
        let tags = analyze_manifest(Some("SEE LICENSE IN GPL-NOTICE.txt"), None, None, None);
        assert!(tags.custom_license);
        assert!(!tags.copyleft_license);
    }

    #[test]
    fn spdx_license_is_not_custom() {
        let tags = analyze_manifest(Some("MIT"), None, None, None);
        assert!(!tags.custom_license);
        assert!(!tags.no_license);
    }

    // ── License: copyleft ─────────────────────────────────────

    #[test]
    fn copyleft_gpl() {
        let tags = analyze_manifest(Some("GPL-3.0"), None, None, None);
        assert!(tags.copyleft_license);
        assert!(!tags.no_license);
    }

    #[test]
    fn copyleft_agpl() {
        let tags = analyze_manifest(Some("AGPL-3.0-or-later"), None, None, None);
        assert!(tags.copyleft_license);
    }

    #[test]
    fn copyleft_lgpl() {
        let tags = analyze_manifest(Some("LGPL-2.1"), None, None, None);
        assert!(tags.copyleft_license);
    }

    #[test]
    fn copyleft_mpl() {
        let tags = analyze_manifest(Some("MPL-2.0"), None, None, None);
        assert!(tags.copyleft_license);
    }

    #[test]
    fn copyleft_in_compound_expression() {
        let tags = analyze_manifest(Some("MIT OR GPL-3.0"), None, None, None);
        assert!(tags.copyleft_license);
    }

    #[test]
    fn copyleft_gpl_2_or_later() {
        let tags = analyze_manifest(Some("GPL-2.0-or-later"), None, None, None);
        assert!(tags.copyleft_license);
    }

    #[test]
    fn not_copyleft_mit() {
        let tags = analyze_manifest(Some("MIT"), None, None, None);
        assert!(!tags.copyleft_license);
        assert!(!tags.no_license);
    }

    #[test]
    fn not_copyleft_apache() {
        let tags = analyze_manifest(Some("Apache-2.0"), None, None, None);
        assert!(!tags.copyleft_license);
    }

    #[test]
    fn not_copyleft_bsd() {
        let tags = analyze_manifest(Some("BSD-3-Clause"), None, None, None);
        assert!(!tags.copyleft_license);
    }

    #[test]
    fn not_copyleft_mit_or_apache() {
        let tags = analyze_manifest(Some("MIT OR Apache-2.0"), None, None, None);
        assert!(!tags.copyleft_license);
    }

    #[test]
    fn not_copyleft_isc() {
        let tags = analyze_manifest(Some("ISC"), None, None, None);
        assert!(!tags.copyleft_license);
    }

    // ── Dependencies: git ─────────────────────────────────────

    #[test]
    fn detect_git_protocol() {
        let d = deps(&[("my-pkg", "git://github.com/owner/repo.git")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.git_dependency);
    }

    #[test]
    fn detect_git_ssh() {
        let d = deps(&[("my-pkg", "git+ssh://git@github.com/owner/repo.git")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.git_dependency);
    }

    #[test]
    fn detect_git_https() {
        let d = deps(&[("my-pkg", "git+https://github.com/owner/repo.git")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.git_dependency);
    }

    #[test]
    fn detect_github_shorthand() {
        let d = deps(&[("my-pkg", "owner/repo")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.git_dependency);
    }

    #[test]
    fn detect_github_shorthand_with_ref() {
        let d = deps(&[("my-pkg", "owner/repo#develop")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.git_dependency);
    }

    #[test]
    fn detect_github_prefix() {
        let d = deps(&[("my-pkg", "github:owner/repo")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.git_dependency);
    }

    #[test]
    fn detect_github_shorthand_with_semver_ref() {
        let d = deps(&[("pkg", "owner/repo#semver:^1.0.0")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.git_dependency);
    }

    #[test]
    fn protocol_specs_are_not_github_shorthand() {
        for spec in [
            "jsr:@std/datetime@^0.225.0",
            "portal:../local",
            "patch:lodash@npm%3A4.17.21#./lodash.patch",
            "file:../local",
            "workspace:packages/ui",
        ] {
            let d = deps(&[("pkg", spec)]);
            let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
            assert!(!tags.git_dependency, "{spec} is not a git dependency");
        }
    }

    #[test]
    fn no_false_positive_scoped_package() {
        let d = deps(&[("@types/node", "^22.0.0")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(!tags.git_dependency);
    }

    #[test]
    fn no_false_positive_semver() {
        let d = deps(&[("express", "^4.18.2")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(!tags.git_dependency);
    }

    // ── Dependencies: HTTP ────────────────────────────────────

    #[test]
    fn detect_http_dependency() {
        let d = deps(&[("my-pkg", "http://example.com/pkg.tgz")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.http_dependency);
    }

    #[test]
    fn no_false_positive_https() {
        let d = deps(&[("my-pkg", "https://example.com/pkg.tgz")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(!tags.http_dependency);
    }

    // ── Dependencies: wildcard ────────────────────────────────

    #[test]
    fn detect_wildcard_star() {
        let d = deps(&[("my-pkg", "*")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.wildcard_dependency);
    }

    #[test]
    fn detect_wildcard_empty() {
        let d = deps(&[("my-pkg", "")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.wildcard_dependency);
    }

    #[test]
    fn detect_wildcard_latest() {
        let d = deps(&[("my-pkg", "latest")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(tags.wildcard_dependency);
    }

    #[test]
    fn no_false_positive_range() {
        let d = deps(&[("my-pkg", ">=1.0.0")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(!tags.wildcard_dependency);
    }

    // ── Dev dependencies also checked ─────────────────────────

    #[test]
    fn detect_git_in_dev_deps() {
        let dev = deps(&[("my-tool", "github:owner/tool")]);
        let tags = analyze_manifest(Some("MIT"), None, Some(&dev), None);
        assert!(tags.git_dependency);
    }

    // ── Optional dependencies also checked ────────────────────

    #[test]
    fn detect_wildcard_in_optional_deps() {
        let opt = deps(&[("optional-pkg", "*")]);
        let tags = analyze_manifest(Some("MIT"), None, None, Some(&opt));
        assert!(tags.wildcard_dependency);
    }

    // ── Combined ──────────────────────────────────────────────

    #[test]
    fn multiple_issues() {
        let d = deps(&[
            ("a", "git://github.com/x/y.git"),
            ("b", "*"),
            ("c", "http://evil.com/pkg.tgz"),
        ]);
        let tags = analyze_manifest(Some("GPL-3.0"), Some(&d), None, None);
        assert!(tags.git_dependency);
        assert!(tags.wildcard_dependency);
        assert!(tags.http_dependency);
        assert!(tags.copyleft_license);
        assert!(!tags.no_license);
        assert!(!tags.custom_license);
    }

    #[test]
    fn clean_package() {
        let d = deps(&[("express", "^4.18.2"), ("lodash", "~4.17.21")]);
        let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
        assert!(!tags.git_dependency);
        assert!(!tags.http_dependency);
        assert!(!tags.wildcard_dependency);
        assert!(!tags.copyleft_license);
        assert!(!tags.no_license);
        assert!(!tags.custom_license);
    }
}
