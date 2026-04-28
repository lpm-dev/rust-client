//! Manifest specifier classifier (Phase 59.0).
//!
//! Today's resolver classifies dependency specifiers ad-hoc — registry
//! semver ranges and `npm:foo@^1.2.3` aliases go through
//! [`crate::ranges::parse_npm_alias`] + [`crate::ranges::NpmRange`];
//! `workspace:*` is handled by string-prefix checks in
//! `lpm-workspace`; everything else is rejected at the alias parser
//! ([crates/lpm-resolver/src/ranges.rs:323-325]).
//!
//! Phase 59.0 introduces a single classifier site so the resolver,
//! manifest reader, and manifest writer all agree on what each
//! specifier shape means. Centralization closes the back door
//! where a new shape could land without going through the parser
//! and silently slip through.
//!
//! ## Recognized shapes (priority order — first match wins)
//!
//! | Form                                | Variant                                       |
//! |-------------------------------------|-----------------------------------------------|
//! | `""`, `"*"`, `"latest"`, `"^1.2.3"` | [`Specifier::SemverRange`]                    |
//! | `npm:<target>@<range>`              | [`Specifier::NpmAlias`]                       |
//! | `workspace:<rest>`                  | [`Specifier::Workspace`]                      |
//! | `git+<url>[#refspec]`               | [`Specifier::Git`]                            |
//! | `git://<url>[#refspec]`             | [`Specifier::Git`] (URL gets `git+` prefix)   |
//! | `github:user/repo[#ref]`            | [`Specifier::Git`] (expanded to canonical)    |
//! | `gist:<id>[#ref]`                   | [`Specifier::Git`] (expanded)                 |
//! | `bitbucket:user/repo[#ref]`         | [`Specifier::Git`] (expanded)                 |
//! | `gitlab:user/repo[#ref]`            | [`Specifier::Git`] (expanded)                 |
//! | bare `user/repo[#ref]`              | [`Specifier::Git`] (expanded as `github:`)    |
//! | `https?://<url>[#sri]`              | [`Specifier::Tarball`]                        |
//! | `file:<path>`                       | [`Specifier::File`] (Tarball/Directory pre-stat) |
//! | `link:<path>`                       | [`Specifier::Link`]                           |
//! | else, parses as semver              | [`Specifier::SemverRange`]                    |
//!
//! `Specifier::File` cannot decide tarball-vs-directory at parse
//! time — that requires a filesystem stat and the path may not even
//! exist when the manifest is read (e.g., during cold install).
//! The resolver disambiguates post-resolve when it has access to the
//! filesystem.

use std::fmt;

/// Classified dependency specifier from a manifest's `dependencies`,
/// `devDependencies`, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Specifier {
    /// Plain semver range or dist-tag — `^1.2.3`, `~1.0`, `1.2.3`,
    /// `>=1.0 <2.0`, `*`, `latest`. The string is preserved verbatim;
    /// classification into a [`crate::ranges::NpmRange`] happens
    /// downstream.
    SemverRange(String),
    /// `npm:<target>@<range>` — install `<target>` under a local
    /// alias. Phase 40 P2 plumbing.
    NpmAlias { target: String, range: String },
    /// `workspace:<rest>` — `*`, `^`, `~`, or any explicit range.
    /// Resolution happens in `lpm-workspace`; the string after the
    /// `workspace:` prefix is preserved here verbatim.
    Workspace(String),
    /// Remote HTTPS tarball. `integrity` is populated when the URL
    /// has an SRI suffix (`https://e.com/foo.tgz#sha512-...`); the
    /// manifest may also omit it (lockfile then carries
    /// trust-on-first-use under the permissive default; v1 strict
    /// mode requires manifest-declared integrity).
    Tarball {
        url: String,
        integrity: Option<String>,
    },
    /// `file:<path>` — could be a local tarball OR a local directory.
    /// Pre-stat: the resolver disambiguates after touching the
    /// filesystem.
    File { path: String },
    /// `link:<path>` — yarn/pnpm-style symlinked directory dep.
    /// Always a directory; never a tarball.
    Link { path: String },
    /// Git source. URL is normalized to npm-canonical `git+…` form
    /// regardless of input shape (shorthand, bare `user/repo`,
    /// `git://`, etc.). `refspec` is the post-`#` fragment when
    /// present (`#main`, `#v1.2.3`, `#abc123`, `#semver:^1.2.3`).
    Git {
        url: String,
        refspec: Option<String>,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpecifierParseError {
    #[error("npm: alias has empty target: {0:?}")]
    NpmAliasEmptyTarget(String),
    #[error("file: specifier has empty path")]
    FileEmptyPath,
    #[error("link: specifier has empty path")]
    LinkEmptyPath,
    #[error("git specifier has empty URL")]
    GitEmptyUrl,
    #[error("host shorthand has empty body: {0:?}")]
    HostShorthandEmptyBody(String),
    #[error("host shorthand is not user/repo shape: {0:?}")]
    HostShorthandInvalidShape(String),
}

impl Specifier {
    /// Classify a manifest specifier string.
    ///
    /// Whitespace is trimmed. Empty / `*` / `latest` are treated as
    /// the wildcard semver range.
    pub fn parse(input: &str) -> Result<Self, SpecifierParseError> {
        let s = input.trim();

        // Empty + universal wildcards collapse to `*`.
        if s.is_empty() || s == "*" || s == "latest" {
            return Ok(Specifier::SemverRange("*".into()));
        }

        // npm:<target>@<range>
        if let Some(rest) = s.strip_prefix("npm:") {
            return parse_npm_alias_inline(rest);
        }

        // workspace:<rest>
        if let Some(rest) = s.strip_prefix("workspace:") {
            return Ok(Specifier::Workspace(rest.to_string()));
        }

        // git+… — preserve the prefix in the URL (npm canonical form).
        if let Some(after_prefix) = s.strip_prefix("git+") {
            let (url_no_prefix, refspec) = split_at_hash(after_prefix);
            if url_no_prefix.is_empty() {
                return Err(SpecifierParseError::GitEmptyUrl);
            }
            return Ok(Specifier::Git {
                url: format!("git+{url_no_prefix}"),
                refspec,
            });
        }

        // git://<url> — promote to `git+git://...` for canonical form.
        if s.starts_with("git://") {
            let (url, refspec) = split_at_hash(s);
            return Ok(Specifier::Git {
                url: format!("git+{url}"),
                refspec,
            });
        }

        // host shorthand: github:, gist:, bitbucket:, gitlab:
        if let Some(spec) = parse_host_shorthand(s)? {
            return Ok(spec);
        }

        // https://, http:// → Tarball
        if s.starts_with("https://") || s.starts_with("http://") {
            let (url, fragment) = split_at_hash(s);
            // Treat fragment as integrity only when it matches a known
            // SRI algo prefix; otherwise leave it on the URL.
            let (final_url, integrity) = match fragment {
                Some(frag) if is_sri_fragment(&frag) => (url.to_string(), Some(frag)),
                Some(frag) => (format!("{url}#{frag}"), None),
                None => (url.to_string(), None),
            };
            return Ok(Specifier::Tarball {
                url: final_url,
                integrity,
            });
        }

        // file:<path>
        if let Some(rest) = s.strip_prefix("file:") {
            if rest.is_empty() {
                return Err(SpecifierParseError::FileEmptyPath);
            }
            return Ok(Specifier::File {
                path: rest.to_string(),
            });
        }

        // link:<path>
        if let Some(rest) = s.strip_prefix("link:") {
            if rest.is_empty() {
                return Err(SpecifierParseError::LinkEmptyPath);
            }
            return Ok(Specifier::Link {
                path: rest.to_string(),
            });
        }

        // Bare `user/repo[#ref]` shorthand for github. Constraints to
        // disambiguate from semver: exactly one '/', both halves
        // non-empty, no spaces, no leading '@' (which would mean
        // a scoped npm package), and the LHS must NOT itself look
        // like a semver operator or version (`>=1.0/2.0` is not a
        // GitHub repo handle).
        if looks_like_github_shorthand(s) {
            return expand_github_shorthand(s);
        }

        // Everything else: assume semver range. Validation against
        // node_semver happens in NpmRange::parse downstream; we just
        // capture the string verbatim. Specifier::parse never claims
        // the range is *valid* — only that it falls into the semver
        // bucket.
        Ok(Specifier::SemverRange(s.to_string()))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_npm_alias_inline(rest: &str) -> Result<Specifier, SpecifierParseError> {
    // npm:<target>@<range>. Scoped targets (`@types/node`) split on
    // the LAST '@' — same convention as parse_npm_alias in ranges.rs.
    if rest.is_empty() {
        return Err(SpecifierParseError::NpmAliasEmptyTarget(format!(
            "npm:{rest}"
        )));
    }
    let (target, range) = match rest.rfind('@') {
        // No '@' anywhere → bare target with implicit '*' range
        // (matches existing parse_npm_alias `npm:foo` → `*`).
        None => (rest, "*"),
        // Leading '@' (scope marker) with no second '@' → bare scoped
        // target, e.g. `npm:@types/node` → target=`@types/node`.
        Some(0) if !rest[1..].contains('@') => (rest, "*"),
        // Otherwise split: target = before LAST '@', range = after.
        // idx > 0 in this arm — Some(0) with `rest[1..].contains('@')`
        // can't happen because rfind would have returned the later '@'.
        Some(idx) => {
            let r = &rest[idx + 1..];
            (&rest[..idx], if r.is_empty() { "*" } else { r })
        }
    };
    Ok(Specifier::NpmAlias {
        target: target.to_string(),
        range: range.to_string(),
    })
}

fn parse_host_shorthand(s: &str) -> Result<Option<Specifier>, SpecifierParseError> {
    // (prefix, host) pairs for the host-shorthand schemes that
    // require user/repo shape (everything except gist).
    const HOSTS: &[(&str, &str)] = &[
        ("github:", "github.com"),
        ("bitbucket:", "bitbucket.org"),
        ("gitlab:", "gitlab.com"),
    ];
    for (prefix, host) in HOSTS {
        if let Some(body) = s.strip_prefix(prefix) {
            if body.is_empty() {
                return Err(SpecifierParseError::HostShorthandEmptyBody(s.to_string()));
            }
            let (path, refspec) = split_at_hash(body);
            // Symmetry with bare `user/repo`: prefixed forms must
            // also be exactly `user/repo` shape, not multi-segment
            // paths. (Phase 59.0 day-1.5 fix — the v0 of this
            // function accepted any non-empty body.)
            if !is_user_repo_shape(path) {
                return Err(SpecifierParseError::HostShorthandInvalidShape(
                    s.to_string(),
                ));
            }
            let canonical_path = strip_dot_git(path);
            return Ok(Some(Specifier::Git {
                url: format!("git+https://{host}/{canonical_path}.git"),
                refspec,
            }));
        }
    }
    // gist: body is a single ID, not user/repo. Still strip a
    // trailing `.git` so `gist:abc.git` doesn't double-suffix.
    if let Some(body) = s.strip_prefix("gist:") {
        if body.is_empty() {
            return Err(SpecifierParseError::HostShorthandEmptyBody(s.to_string()));
        }
        let (id, refspec) = split_at_hash(body);
        let canonical_id = strip_dot_git(id);
        return Ok(Some(Specifier::Git {
            url: format!("git+https://gist.github.com/{canonical_id}.git"),
            refspec,
        }));
    }
    Ok(None)
}

/// Structural check: is `s` a `user/repo` handle?
///
/// Used by both the bare-shorthand path (with an additional
/// bad-lead-char check at [`looks_like_github_shorthand`] to
/// disambiguate from semver) and the prefixed-shorthand path
/// (where the prefix already disambiguates). Path-handle char set
/// matches GitHub/GitLab/Bitbucket repo-name rules: ASCII
/// alphanumerics plus `-`, `_`, `.`.
fn is_user_repo_shape(s: &str) -> bool {
    let Some((lhs, rhs)) = s.split_once('/') else {
        return false;
    };
    if lhs.is_empty() || rhs.is_empty() {
        return false;
    }
    if rhs.contains('/') {
        return false;
    }
    let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    lhs.chars().all(valid_char) && rhs.chars().all(valid_char)
}

fn looks_like_github_shorthand(s: &str) -> bool {
    // Bare `user/repo[#ref]` — `is_user_repo_shape` plus a
    // bad-leading-char check to keep `>=1.0/2.0` from being
    // misclassified as a github handle.
    let head = s.split_once('#').map(|(h, _)| h).unwrap_or(s);
    let bad_lead = matches!(
        head.chars().next(),
        Some('@' | '>' | '<' | '=' | '~' | '^' | '.' | '/')
    );
    if bad_lead {
        return false;
    }
    is_user_repo_shape(head)
}

fn expand_github_shorthand(s: &str) -> Result<Specifier, SpecifierParseError> {
    // Pre-validated by looks_like_github_shorthand; this is the
    // expansion step. Strip `.git` before re-adding so an input of
    // `foo/bar.git` doesn't canonicalize to `foo/bar.git.git`.
    let (path, refspec) = split_at_hash(s);
    let canonical_path = strip_dot_git(path);
    Ok(Specifier::Git {
        url: format!("git+https://github.com/{canonical_path}.git"),
        refspec,
    })
}

/// Strip a trailing `.git` if present. Used during host-shorthand
/// expansion so the canonicalized URL has exactly one `.git`
/// suffix regardless of whether the user wrote `foo/bar` or
/// `foo/bar.git`.
fn strip_dot_git(s: &str) -> &str {
    s.strip_suffix(".git").unwrap_or(s)
}

fn split_at_hash(s: &str) -> (&str, Option<String>) {
    match s.split_once('#') {
        Some((before, after)) if !after.is_empty() => (before, Some(after.to_string())),
        Some((before, _empty)) => (before, None),
        None => (s, None),
    }
}

fn is_sri_fragment(frag: &str) -> bool {
    // SRI is `<algo>-<base64>`. We accept the algos npm/yarn/lpm
    // currently recognize.
    const ALGOS: &[&str] = &["sha512-", "sha384-", "sha256-", "sha1-", "md5-"];
    ALGOS.iter().any(|a| frag.starts_with(a))
}

// ── Display: round-trippable canonical form ─────────────────────────────────
// Display is for diagnostics; the lockfile stores parsed forms as
// `Source` strings, not raw `Specifier` strings. We still want a
// stable, parseable canonical form for log messages and tests.

impl fmt::Display for Specifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Specifier::SemverRange(r) => write!(f, "{r}"),
            Specifier::NpmAlias { target, range } => write!(f, "npm:{target}@{range}"),
            Specifier::Workspace(rest) => write!(f, "workspace:{rest}"),
            Specifier::Tarball {
                url,
                integrity: Some(i),
            } => write!(f, "{url}#{i}"),
            Specifier::Tarball {
                url,
                integrity: None,
            } => write!(f, "{url}"),
            Specifier::File { path } => write!(f, "file:{path}"),
            Specifier::Link { path } => write!(f, "link:{path}"),
            Specifier::Git {
                url,
                refspec: Some(r),
            } => write!(f, "{url}#{r}"),
            Specifier::Git { url, refspec: None } => write!(f, "{url}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Specifier {
        Specifier::parse(s).unwrap_or_else(|e| panic!("parse {s:?} failed: {e}"))
    }

    // ── SemverRange ──────────────────────────────────────────────────────────

    #[test]
    fn semver_caret() {
        assert_eq!(parse("^1.2.3"), Specifier::SemverRange("^1.2.3".into()));
    }

    #[test]
    fn semver_tilde() {
        assert_eq!(parse("~1.2"), Specifier::SemverRange("~1.2".into()));
    }

    #[test]
    fn semver_exact() {
        assert_eq!(parse("1.2.3"), Specifier::SemverRange("1.2.3".into()));
    }

    #[test]
    fn semver_or_range() {
        assert_eq!(
            parse("^1.0.0 || ^2.0.0"),
            Specifier::SemverRange("^1.0.0 || ^2.0.0".into())
        );
    }

    #[test]
    fn empty_string_is_wildcard() {
        assert_eq!(parse(""), Specifier::SemverRange("*".into()));
    }

    #[test]
    fn star_is_wildcard() {
        assert_eq!(parse("*"), Specifier::SemverRange("*".into()));
    }

    #[test]
    fn latest_is_wildcard() {
        assert_eq!(parse("latest"), Specifier::SemverRange("*".into()));
    }

    #[test]
    fn whitespace_is_trimmed() {
        assert_eq!(parse("  ^1.0.0  "), Specifier::SemverRange("^1.0.0".into()));
    }

    // ── NpmAlias ─────────────────────────────────────────────────────────────

    #[test]
    fn npm_alias_plain() {
        assert_eq!(
            parse("npm:strip-ansi@^6.0.1"),
            Specifier::NpmAlias {
                target: "strip-ansi".into(),
                range: "^6.0.1".into(),
            }
        );
    }

    #[test]
    fn npm_alias_scoped_splits_on_last_at() {
        assert_eq!(
            parse("npm:@types/node@^20.0.0"),
            Specifier::NpmAlias {
                target: "@types/node".into(),
                range: "^20.0.0".into(),
            }
        );
    }

    #[test]
    fn npm_alias_bare_target_implies_wildcard() {
        assert_eq!(
            parse("npm:foo"),
            Specifier::NpmAlias {
                target: "foo".into(),
                range: "*".into(),
            }
        );
    }

    #[test]
    fn npm_alias_scoped_bare_target_implies_wildcard() {
        assert_eq!(
            parse("npm:@types/node"),
            Specifier::NpmAlias {
                target: "@types/node".into(),
                range: "*".into(),
            }
        );
    }

    #[test]
    fn npm_alias_trailing_at_is_wildcard() {
        assert_eq!(
            parse("npm:foo@"),
            Specifier::NpmAlias {
                target: "foo".into(),
                range: "*".into(),
            }
        );
    }

    #[test]
    fn npm_alias_empty_body_errors() {
        assert!(matches!(
            Specifier::parse("npm:"),
            Err(SpecifierParseError::NpmAliasEmptyTarget(_))
        ));
    }

    // ── Workspace ────────────────────────────────────────────────────────────

    #[test]
    fn workspace_star() {
        assert_eq!(parse("workspace:*"), Specifier::Workspace("*".into()));
    }

    #[test]
    fn workspace_caret() {
        assert_eq!(parse("workspace:^"), Specifier::Workspace("^".into()));
    }

    #[test]
    fn workspace_tilde() {
        assert_eq!(parse("workspace:~"), Specifier::Workspace("~".into()));
    }

    #[test]
    fn workspace_explicit_range() {
        assert_eq!(
            parse("workspace:>=1.0.0"),
            Specifier::Workspace(">=1.0.0".into())
        );
    }

    // ── Git (git+ form) ──────────────────────────────────────────────────────

    #[test]
    fn git_https() {
        assert_eq!(
            parse("git+https://github.com/foo/bar.git"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn git_ssh() {
        assert_eq!(
            parse("git+ssh://git@github.com:foo/bar.git"),
            Specifier::Git {
                url: "git+ssh://git@github.com:foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn git_with_refspec() {
        assert_eq!(
            parse("git+https://github.com/foo/bar.git#main"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: Some("main".into()),
            }
        );
    }

    #[test]
    fn git_with_semver_refspec() {
        assert_eq!(
            parse("git+https://github.com/foo/bar.git#semver:^1.2.3"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: Some("semver:^1.2.3".into()),
            }
        );
    }

    #[test]
    fn git_protocol_promotes_to_git_plus() {
        // `git://` with no `git+` prefix gets promoted to canonical form.
        assert_eq!(
            parse("git://github.com/foo/bar.git"),
            Specifier::Git {
                url: "git+git://github.com/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn git_empty_url_errors() {
        assert!(matches!(
            Specifier::parse("git+"),
            Err(SpecifierParseError::GitEmptyUrl)
        ));
    }

    // ── Host shorthand expansion ─────────────────────────────────────────────

    #[test]
    fn github_shorthand() {
        assert_eq!(
            parse("github:foo/bar"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn github_shorthand_with_ref() {
        assert_eq!(
            parse("github:foo/bar#main"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: Some("main".into()),
            }
        );
    }

    #[test]
    fn bitbucket_shorthand() {
        assert_eq!(
            parse("bitbucket:foo/bar"),
            Specifier::Git {
                url: "git+https://bitbucket.org/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn gitlab_shorthand() {
        assert_eq!(
            parse("gitlab:foo/bar"),
            Specifier::Git {
                url: "git+https://gitlab.com/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn gist_shorthand() {
        assert_eq!(
            parse("gist:abc123"),
            Specifier::Git {
                url: "git+https://gist.github.com/abc123.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn github_empty_body_errors() {
        assert!(matches!(
            Specifier::parse("github:"),
            Err(SpecifierParseError::HostShorthandEmptyBody(_))
        ));
    }

    // ── Host shorthand: `.git` suffix is canonicalized, not duplicated ──────

    #[test]
    fn github_shorthand_with_dot_git_suffix() {
        // `github:foo/bar.git` must canonicalize to a single `.git`,
        // not `git+https://github.com/foo/bar.git.git`.
        assert_eq!(
            parse("github:foo/bar.git"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn bitbucket_shorthand_with_dot_git_suffix() {
        assert_eq!(
            parse("bitbucket:foo/bar.git"),
            Specifier::Git {
                url: "git+https://bitbucket.org/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn gitlab_shorthand_with_dot_git_suffix() {
        assert_eq!(
            parse("gitlab:foo/bar.git"),
            Specifier::Git {
                url: "git+https://gitlab.com/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn gist_shorthand_with_dot_git_suffix() {
        assert_eq!(
            parse("gist:abc123.git"),
            Specifier::Git {
                url: "git+https://gist.github.com/abc123.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn github_shorthand_dot_git_with_refspec() {
        // The `.git` strip happens BEFORE re-adding, even when a
        // refspec is appended.
        assert_eq!(
            parse("github:foo/bar.git#main"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: Some("main".into()),
            }
        );
    }

    #[test]
    fn bare_user_repo_with_dot_git_suffix() {
        assert_eq!(
            parse("foo/bar.git"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn bare_user_repo_dot_git_with_refspec() {
        assert_eq!(
            parse("foo/bar.git#v1.0.0"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: Some("v1.0.0".into()),
            }
        );
    }

    // ── Host shorthand: shape validation symmetric with bare form ───────────

    #[test]
    fn github_shorthand_multi_segment_path_errors() {
        // `github:foo/bar/baz` is not a valid user/repo handle —
        // must be rejected, not expanded to a 3-segment URL path.
        assert!(matches!(
            Specifier::parse("github:foo/bar/baz"),
            Err(SpecifierParseError::HostShorthandInvalidShape(_))
        ));
    }

    #[test]
    fn bitbucket_shorthand_multi_segment_path_errors() {
        assert!(matches!(
            Specifier::parse("bitbucket:foo/bar/baz"),
            Err(SpecifierParseError::HostShorthandInvalidShape(_))
        ));
    }

    #[test]
    fn gitlab_shorthand_multi_segment_path_errors() {
        assert!(matches!(
            Specifier::parse("gitlab:foo/bar/baz"),
            Err(SpecifierParseError::HostShorthandInvalidShape(_))
        ));
    }

    #[test]
    fn github_shorthand_no_slash_errors() {
        // `github:foo` has no `/` separator — not user/repo shape.
        assert!(matches!(
            Specifier::parse("github:foo"),
            Err(SpecifierParseError::HostShorthandInvalidShape(_))
        ));
    }

    #[test]
    fn github_shorthand_empty_lhs_errors() {
        assert!(matches!(
            Specifier::parse("github:/foo"),
            Err(SpecifierParseError::HostShorthandInvalidShape(_))
        ));
    }

    #[test]
    fn github_shorthand_empty_rhs_errors() {
        assert!(matches!(
            Specifier::parse("github:foo/"),
            Err(SpecifierParseError::HostShorthandInvalidShape(_))
        ));
    }

    #[test]
    fn github_shorthand_invalid_chars_errors() {
        assert!(matches!(
            Specifier::parse("github:foo/bar baz"),
            Err(SpecifierParseError::HostShorthandInvalidShape(_))
        ));
    }

    // ── Bare user/repo shorthand ─────────────────────────────────────────────

    #[test]
    fn bare_user_repo_treated_as_github() {
        assert_eq!(
            parse("foo/bar"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: None,
            }
        );
    }

    #[test]
    fn bare_user_repo_with_ref() {
        assert_eq!(
            parse("foo/bar#v1.0.0"),
            Specifier::Git {
                url: "git+https://github.com/foo/bar.git".into(),
                refspec: Some("v1.0.0".into()),
            }
        );
    }

    #[test]
    fn scoped_npm_pkg_is_not_treated_as_repo_handle() {
        // `@types/node` looks like `<word>/<word>` but starts with '@'
        // → it's a scoped npm package name, not a github repo. Should
        // fall through to SemverRange (downstream code treats this as
        // a malformed semver range, but Specifier::parse just classifies).
        assert_eq!(
            parse("@types/node"),
            Specifier::SemverRange("@types/node".into())
        );
    }

    #[test]
    fn semver_with_slash_is_not_repo_handle() {
        // `>=1.0/2.0` shouldn't trigger github-shorthand; the leading
        // `>` is rejected.
        assert_eq!(
            parse(">=1.0/2.0"),
            Specifier::SemverRange(">=1.0/2.0".into())
        );
    }

    #[test]
    fn multi_slash_is_not_repo_handle() {
        // `a/b/c` has too many slashes — not a github handle.
        assert_eq!(parse("a/b/c"), Specifier::SemverRange("a/b/c".into()));
    }

    // ── Tarball ──────────────────────────────────────────────────────────────

    #[test]
    fn tarball_https_no_integrity() {
        assert_eq!(
            parse("https://example.com/foo-1.0.0.tgz"),
            Specifier::Tarball {
                url: "https://example.com/foo-1.0.0.tgz".into(),
                integrity: None,
            }
        );
    }

    #[test]
    fn tarball_http_no_integrity() {
        assert_eq!(
            parse("http://example.com/foo.tgz"),
            Specifier::Tarball {
                url: "http://example.com/foo.tgz".into(),
                integrity: None,
            }
        );
    }

    #[test]
    fn tarball_with_sri_integrity() {
        assert_eq!(
            parse("https://example.com/foo.tgz#sha512-abcdef"),
            Specifier::Tarball {
                url: "https://example.com/foo.tgz".into(),
                integrity: Some("sha512-abcdef".into()),
            }
        );
    }

    #[test]
    fn tarball_with_sha256_integrity() {
        assert_eq!(
            parse("https://example.com/foo.tgz#sha256-abc"),
            Specifier::Tarball {
                url: "https://example.com/foo.tgz".into(),
                integrity: Some("sha256-abc".into()),
            }
        );
    }

    #[test]
    fn tarball_non_sri_fragment_kept_in_url() {
        // A `#anchor` that isn't an SRI hash is preserved on the URL,
        // not treated as integrity.
        assert_eq!(
            parse("https://example.com/foo.tgz#anchor"),
            Specifier::Tarball {
                url: "https://example.com/foo.tgz#anchor".into(),
                integrity: None,
            }
        );
    }

    // ── File / Link ──────────────────────────────────────────────────────────

    #[test]
    fn file_relative_directory() {
        assert_eq!(
            parse("file:../packages/foo"),
            Specifier::File {
                path: "../packages/foo".into()
            }
        );
    }

    #[test]
    fn file_relative_tarball() {
        // Pre-stat: parse can't tell directory from tarball.
        assert_eq!(
            parse("file:./local/foo.tgz"),
            Specifier::File {
                path: "./local/foo.tgz".into()
            }
        );
    }

    #[test]
    fn file_empty_path_errors() {
        assert!(matches!(
            Specifier::parse("file:"),
            Err(SpecifierParseError::FileEmptyPath)
        ));
    }

    #[test]
    fn link_relative_directory() {
        assert_eq!(
            parse("link:../packages/foo"),
            Specifier::Link {
                path: "../packages/foo".into()
            }
        );
    }

    #[test]
    fn link_empty_path_errors() {
        assert!(matches!(
            Specifier::parse("link:"),
            Err(SpecifierParseError::LinkEmptyPath)
        ));
    }

    // ── Display round-trip ───────────────────────────────────────────────────

    #[test]
    fn display_round_trips_github_to_canonical() {
        // Display emits the canonical (post-expansion) form, not the
        // user's input. `github:foo/bar` round-trips as
        // `git+https://github.com/foo/bar.git` — that's correct: the
        // resolver works in canonical form.
        let parsed = parse("github:foo/bar");
        let displayed = parsed.to_string();
        assert_eq!(displayed, "git+https://github.com/foo/bar.git");
        let reparsed = parse(&displayed);
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn display_round_trips_tarball_with_integrity() {
        let s = "https://e.com/foo.tgz#sha512-abc";
        let parsed = parse(s);
        assert_eq!(parsed.to_string(), s);
        assert_eq!(parse(&parsed.to_string()), parsed);
    }

    #[test]
    fn display_round_trips_workspace() {
        let s = "workspace:^1.2.3";
        let parsed = parse(s);
        assert_eq!(parsed.to_string(), s);
        assert_eq!(parse(&parsed.to_string()), parsed);
    }
}
