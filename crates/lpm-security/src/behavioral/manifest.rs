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
/// to a specific package.json parser. The dependency tags read only the
/// dependencies a consumer installs: `devDependencies` never reach them.
/// `peer_dependencies` holds the peers an install adds on its own, as npm
/// does since version 7: those `peerDependenciesMeta` doesn't mark optional.
/// A peer's git or `http:` source counts, but an any-version peer range is
/// how a plugin names its host, so it isn't a wildcard dependency.
pub fn analyze_manifest(
    license: Option<&str>,
    dependencies: Option<&HashMap<String, String>>,
    optional_dependencies: Option<&HashMap<String, String>>,
    peer_dependencies: Option<&HashMap<String, String>>,
) -> ManifestTags {
    analyze_manifest_with_privacy(
        license,
        false,
        dependencies,
        optional_dependencies,
        peer_dependencies,
    )
}

/// [`analyze_manifest`] for a package that may be `private`, which needs no
/// license.
pub fn analyze_manifest_with_privacy(
    license: Option<&str>,
    private_package: bool,
    dependencies: Option<&HashMap<String, String>>,
    optional_dependencies: Option<&HashMap<String, String>>,
    peer_dependencies: Option<&HashMap<String, String>>,
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

    let installed = [dependencies, optional_dependencies]
        .into_iter()
        .flatten()
        .flat_map(|deps| deps.values().map(|version| (version, false)));
    let peers = peer_dependencies
        .into_iter()
        .flat_map(|deps| deps.values().map(|version| (version, true)));
    for (version, peer) in installed.chain(peers) {
        let v = version.trim();

        if is_git_source(v) {
            tags.git_dependency = true;
        }

        // HTTP dependencies (insecure transport)
        if v.get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
        {
            tags.http_dependency = true;
        }

        // Wildcard dependencies
        if !peer && (v == "*" || v.is_empty() || v == "latest") {
            tags.wildcard_dependency = true;
        }
    }

    tags
}

/// Whether npm installs a dependency spec from a git repository, which sets
/// the git dependency tag: a git URL (`git:` with or without `//`, `git+…:`,
/// `ssh://`, or `user@host:path` as scp writes it), a host shortcut
/// (`github:`, `gitlab:`, `bitbucket:`, `gist:`, `sourcehut:`), a repository
/// URL on a git host ([`is_hosted_repository_url`]), or `owner/repo`
/// shorthand. Schemes compare in any case, as npm parses them. A caller that
/// acts on the tag, such as a scanner that reviews each git spec, can find
/// the specs that set it with this.
pub fn is_git_source(spec: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "git:",
        "git+",
        "ssh://",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
        "sourcehut:",
    ];
    let spec = spec.trim();
    let starts_with = |prefix: &str| {
        spec.get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
    };
    PREFIXES.iter().any(|prefix| starts_with(prefix))
        || is_scp_git_url(spec)
        || is_hosted_repository_url(spec)
        || is_repo_shorthand(spec)
}

/// `user@host:path`, the scp form of an ssh git URL.
fn is_scp_git_url(spec: &str) -> bool {
    !spec.contains("://")
        && !spec.bytes().any(|byte| byte.is_ascii_whitespace())
        && spec
            .find('@')
            .zip(spec.find(':'))
            .is_some_and(|(at, colon)| at > 0 && at < colon && colon + 1 < spec.len())
}

/// A repository URL that npm clones rather than downloads, by
/// hosted-git-info's rules, which npm uses. The URL parses as WHATWG URLs do
/// (case, port, credentials and dot segments don't matter), and its host,
/// without `www.`, decides the rest:
/// - `github.com` (`https:` or `http:`): `/owner/repo`, optionally
///   `/tree/<ref>`. Any other path below the repository is a file or an
///   archive.
/// - `gitlab.com`: `/group/…/repo`, with any depth of subgroups, but no
///   `/-/` or `/archive.tar.gz`.
/// - `bitbucket.org`: `/owner/repo`, unless a `/get/` archive follows.
/// - `gist.github.com`: `/owner/id` or `/id`, unless `/raw` follows.
/// - `git.sr.ht`: `/~owner/repo`, unless an `/archive/` follows.
///
/// A trailing `.git` is dropped from the repository's name, and a part
/// whose percent-encoding doesn't decode makes the URL a download.
fn is_hosted_repository_url(spec: &str) -> bool {
    let Ok(url) = url::Url::parse(spec) else {
        return false;
    };
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        _ => return false,
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.strip_prefix("www.").unwrap_or(host);
    let fragment = url.fragment().unwrap_or("");
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    // hosted-git-info splits with a limit, so parts past it are ignored.
    let mut parts = path.split('/');
    let mut part = || parts.next().unwrap_or("");
    let repository = |name: &str| name.strip_suffix(".git").unwrap_or(name).to_owned();
    let (owner, name, reference) = match host {
        "github.com" => {
            let (owner, name, kind) = (part(), repository(part()), part());
            let reference = match kind {
                "" => fragment,
                "tree" => part(),
                _ => return false,
            };
            (owner.to_owned(), name, reference)
        }
        "gitlab.com" if https => {
            if path.contains("/-/") || path.contains("/archive.tar.gz") {
                return false;
            }
            let (group, name) = path.rsplit_once('/').unwrap_or(("", path));
            (group.to_owned(), repository(name), fragment)
        }
        "bitbucket.org" if https => {
            let (owner, name) = (part(), repository(part()));
            if part() == "get" {
                return false;
            }
            (owner.to_owned(), name, fragment)
        }
        "git.sr.ht" if https => {
            let (owner, name) = (part(), repository(part()));
            if part() == "archive" {
                return false;
            }
            (owner.to_owned(), name, fragment)
        }
        "gist.github.com" if https => {
            let (first, second) = (part(), part());
            if part() == "raw" {
                return false;
            }
            return match (first, second) {
                ("", "") => false,
                (id, "") => percent_decodes(id),
                (owner, id) => percent_decodes(owner) && percent_decodes(id),
            } && percent_decodes(fragment);
        }
        _ => return false,
    };
    !owner.is_empty()
        && !name.is_empty()
        && percent_decodes(&owner)
        && percent_decodes(&name)
        && percent_decodes(reference)
}

/// Whether `component` decodes as JavaScript's `decodeURIComponent` decodes
/// it: each `%` starts two hex digits, and the bytes are UTF-8.
fn percent_decodes(component: &str) -> bool {
    let bytes = component.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let digits = bytes
                .get(index + 1..index + 3)
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| u8::from_str_radix(digits, 16).ok());
            let Some(byte) = digits else {
                return false;
            };
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    std::str::from_utf8(&decoded).is_ok()
}

/// `owner/repo` shorthand, optionally with `#ref`, which npm installs from
/// GitHub, by hosted-git-info's rule, which npm uses: before any `#`, one
/// slash after the first character, and no `:` (a protocol such as `jsr:`
/// or `file:`), `@` or whitespace. A trailing slash or a second one makes a
/// local folder (`packages/core/lib`, `vendor/helper/`), as do `.`, `/` and
/// `~/` at the start.
fn is_repo_shorthand(spec: &str) -> bool {
    if spec.starts_with('.') || spec.starts_with("~/") {
        return false;
    }
    let head = spec.split_once('#').map_or(spec, |(head, _)| head);
    head.find('/').is_some_and(|slash| slash > 0)
        && head.bytes().filter(|&byte| byte == b'/').count() == 1
        && !head.ends_with('/')
        && !head
            .bytes()
            .any(|byte| matches!(byte, b':' | b'@') || byte.is_ascii_whitespace())
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
    fn git_file_urls_and_gist_shorthand_are_git_dependencies() {
        for spec in [
            "git+file:///srv/repos/kit.git",
            "gist:11081aaa281",
            "gist:owner/11081aaa281",
            "npm/cl%69",
            "owner/repo#semver:^1.0.0 || ^2.0.0",
            "GIT+SSH://git@github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
            "ssh://git@github.com/owner/repo.git",
            "https://github.com/owner/repo",
            "https://gitlab.com/owner/repo.git#v1",
            "sourcehut:~owner/repo",
            "git+rsync://example.com/repo",
        ] {
            let d = deps(&[("pkg", spec)]);
            let tags = analyze_manifest(Some("MIT"), Some(&d), None, None);
            assert!(tags.git_dependency, "{spec} is a git dependency");
        }
    }

    #[test]
    fn tarball_urls_on_a_git_host_are_not_git_dependencies_and_http_is_any_case() {
        let d = deps(&[("pkg", "https://github.com/owner/repo/archive/v1.0.0.tar.gz")]);
        assert!(!analyze_manifest(Some("MIT"), Some(&d), None, None).git_dependency);
        let d = deps(&[("pkg", "HTTP://example.com/pkg.tgz")]);
        assert!(analyze_manifest(Some("MIT"), Some(&d), None, None).http_dependency);
    }

    #[test]
    fn repository_urls_are_git_dependencies_by_each_hosts_rules_as_npm_reads_them() {
        let git = |spec: &str| {
            let d = deps(&[("pkg", spec)]);
            analyze_manifest(Some("MIT"), Some(&d), None, None).git_dependency
        };
        for spec in [
            "https://gitlab.com/group/subgroup/repo",
            "https://gitlab.com/group/subgroup/repo.git#v1",
            "https://gist.github.com/owner/11081aaa281",
            "https://gist.github.com/11081aaa281",
            "https://github.com:443/owner/repo",
            "https://github.com:8443/owner/repo",
            "https://token@github.com/owner/repo",
            "HTTPS://WWW.GITHUB.COM/owner/repo",
            "https://github.com/owner/repo/",
            "https://github.com/owner/repo/tree/main",
            "http://github.com/owner/repo",
            "https://bitbucket.org/owner/repo/src/main",
            "https://git.sr.ht/~owner/repo",
            "https://github.com/owner/repo/../other",
            "git:github.com/owner/repo",
            "GIT:github.com/owner/repo",
        ] {
            assert!(git(spec), "{spec} is a git dependency");
        }
        for spec in [
            "https://gitlab.com/group/repo/-/archive/v1/repo-v1.tar.gz",
            "https://gitlab.com/group/repo/",
            "https://gist.github.com/owner/11081aaa281/raw",
            "https://github.com/owner/repo/blob/main/index.js",
            "https://github.com/owner",
            "https://github.com/owner/.git",
            "https://github.com/owner/%zz",
            "http://gitlab.com/group/repo",
            "http://bitbucket.org/owner/repo",
            "https://bitbucket.org/owner/repo/get/v1.tar.gz",
            "https://git.sr.ht/~owner/repo/archive/v1.tar.gz",
            "https://codeload.github.com/owner/repo/tar.gz/main",
        ] {
            assert!(!git(spec), "{spec} is downloaded, not cloned");
        }
    }

    #[test]
    fn local_folder_paths_are_not_github_shorthand() {
        for spec in [
            "../../../packages/core",
            "./vendor/helper",
            "../sibling",
            "packages/core/lib",
            "vendor/helper/",
            "~/projects/kit",
        ] {
            let d = deps(&[("pkg", spec)]);
            let tags = analyze_manifest(Some("MIT"), Some(&d), None, Some(&d));
            assert!(!tags.git_dependency, "{spec} is a local folder");
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

    // ── Optional dependencies also checked ────────────────────

    #[test]
    fn detect_wildcard_in_optional_deps() {
        let opt = deps(&[("optional-pkg", "*")]);
        let tags = analyze_manifest(Some("MIT"), None, Some(&opt), None);
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
