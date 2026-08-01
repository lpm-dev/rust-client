//! Source discriminator for non-registry dependency sources.
//!
//! The lockfile encodes source as a flat `Option<String>` on
//! [`crate::LockedPackage`] — e.g. `"registry+https://registry.npmjs.org"`.
//! The wire format is flat (one string per package entry) but a typed
//! enum provides parsed access. [`Source::parse`] and the `Display`
//! impl are the only conversion boundaries.
//!
//! ## Wire format
//!
//! ```text
//! registry+<url>           # npm-style registry (existing, unchanged)
//! tarball+<url-or-path>    # remote https tarball OR local file: tarball
//! directory+<path>         # file: directory dep
//! link+<path>              # link: directory dep (yarn/pnpm style)
//! git+<url>#<commit>       # git source pinned to an exact commit; URL retains
//!                          # the npm-canonical `git+` prefix
//! ```
//!
//! Each non-Registry variant carries only "where it came from".
//! Sibling fields on [`crate::LockedPackage`] hold:
//! - `integrity` — SRI hash (relevant for Registry + Tarball)
//! - `tarball` — dist-URL field-hint, valid only when the source kind
//!   is Registry. Kept distinct from `Source::Tarball`; conflation
//!   would let `lpm update` silently swap a tarball-URL dep for a
//!   registry package with the same dist URL.
//!
//! The user-written ref remains in the importer snapshot. The package
//! source contains the resolved commit so source identity, root
//! selection, and binary lockfile replay all use the same immutable
//! value.

use lpm_common::integrity::{HashAlgorithm, Integrity};
use std::fmt;

/// Source discriminator for a lockfile package entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Source {
    /// npm-compatible registry. URL points at the registry root
    /// (e.g., `https://registry.npmjs.org`), not a specific tarball.
    Registry { url: String },
    /// Remote HTTPS tarball or local file: tarball. The URL/path is
    /// the **identity** — distinct from the per-entry `tarball`
    /// field-hint, which is a dist-URL cache valid only for
    /// `Source::Registry`.
    Tarball { url: String },
    /// `file:` directory dep. Path is relative to the lockfile's
    /// directory; resolved at install time.
    Directory { path: String },
    /// `link:` directory dep. Always wrapper-symlinked (yarn/pnpm
    /// semantics).
    Link { path: String },
    /// Git source pinned to a commit. URL retains the npm-canonical
    /// `git+` prefix and ends in `#<40-character commit>`.
    Git { url: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SourceParseError {
    #[error("source string is empty")]
    Empty,
    #[error(
        "unknown source kind {0:?} (expected one of: registry+, tarball+, directory+, link+, git+)"
    )]
    UnknownKind(String),
    #[error("source kind '{kind}' has empty value")]
    EmptyValue { kind: String },
}

impl Source {
    /// Short stable identifier for this source.
    ///
    /// Used to disambiguate two packages with the same `(name,
    /// version)` that come from different sources — needed in
    /// lockfile keys, store paths, and resolver fixed-assignment
    /// slots.
    ///
    /// All variants use a prefix + 16-hex truncated-SHA-256 digest
    /// of the canonical source string:
    /// - `Source::Registry`  → `"npm-{16hex}"` (hashes the registry URL)
    /// - `Source::Tarball`   → `"t-{16hex}"`
    /// - `Source::Directory` → `"f-{16hex}"` (`f` for `file:`)
    /// - `Source::Link`      → `"l-{16hex}"`
    /// - `Source::Git`       → `"g-{16hex}"`
    ///
    /// A constant `"npm"` sentinel for Registry was considered, but
    /// breaks with private-mirror-with-overrides, the same
    /// `name@version` resolved from npm.org vs Verdaccio,
    /// mixed-scope monorepos with per-subtree `.npmrc`, and lockfile
    /// portability across teams on different registry origins.
    /// Including the URL hash makes `source_id` lossless across all
    /// of these.
    ///
    /// 16 hex chars (= 64 bits) is well below the birthday bound
    /// for any realistic graph size and keeps the suffix short
    /// enough to inline into lockfile keys without bloat.
    pub fn source_id(&self) -> String {
        match self {
            Source::Registry { url } => format!("npm-{}", hash16(url)),
            Source::Tarball { url } => format!("t-{}", hash16(url)),
            Source::Directory { path } => format!("f-{}", hash16(path)),
            Source::Link { path } => format!("l-{}", hash16(path)),
            Source::Git { url } => format!("g-{}", hash16(url)),
        }
    }

    /// Parse a lockfile source string into a typed [`Source`].
    ///
    /// Recognized prefixes — see module docs for the wire format.
    ///
    /// `git+` is special: the prefix is **retained** in the URL
    /// (`Source::Git { url: "git+https://..." }`) because npm's
    /// canonical git URL form keeps it. All other prefixes are
    /// stripped from the stored value.
    pub fn parse(s: &str) -> Result<Self, SourceParseError> {
        if s.is_empty() {
            return Err(SourceParseError::Empty);
        }

        if let Some(rest) = s.strip_prefix("registry+") {
            return non_empty(rest, "registry").map(|url| Source::Registry { url });
        }
        if let Some(rest) = s.strip_prefix("tarball+") {
            return non_empty(rest, "tarball").map(|url| Source::Tarball { url });
        }
        if let Some(rest) = s.strip_prefix("directory+") {
            return non_empty(rest, "directory").map(|path| Source::Directory { path });
        }
        if let Some(rest) = s.strip_prefix("link+") {
            return non_empty(rest, "link").map(|path| Source::Link { path });
        }
        if s.starts_with("git+") {
            // git+ is the discriminator AND part of the canonical URL.
            // `git+` alone (4 bytes, no body) is a malformed entry.
            if s.len() == 4 {
                return Err(SourceParseError::EmptyValue { kind: "git".into() });
            }
            return Ok(Source::Git { url: s.to_string() });
        }

        // No known prefix matched. Surface the user-typed kind for
        // a clearer error message; everything before the first '+'
        // (or the whole string if there's no '+') is what they wrote.
        let kind = s.split_once('+').map_or(s, |(k, _)| k);
        Err(SourceParseError::UnknownKind(kind.to_string()))
    }
}

/// Compute the 16-hex truncated SHA-256 digest of `s`.
///
/// Reuses [`lpm_common::integrity::Integrity::from_bytes`] so the
/// hashing implementation is shared with the SRI machinery (single
/// source of truth, no duplicate sha2 wiring in `lpm-lockfile`).
/// 16 hex chars = first 8 bytes of the digest (= 64 bits).
fn hash16(s: &str) -> String {
    let int = Integrity::from_bytes(HashAlgorithm::Sha256, s.as_bytes());
    int.hash
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn non_empty(rest: &str, kind: &str) -> Result<String, SourceParseError> {
    if rest.is_empty() {
        Err(SourceParseError::EmptyValue {
            kind: kind.to_string(),
        })
    } else {
        Ok(rest.to_string())
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Registry { url } => write!(f, "registry+{url}"),
            Source::Tarball { url } => write!(f, "tarball+{url}"),
            Source::Directory { path } => write!(f, "directory+{path}"),
            Source::Link { path } => write!(f, "link+{path}"),
            // Git URLs carry the `git+` prefix in the URL itself.
            Source::Git { url } => write!(f, "{url}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Registry (existing format, unchanged) ────────────────────────────────

    #[test]
    fn parse_registry_npm() {
        assert_eq!(
            Source::parse("registry+https://registry.npmjs.org").unwrap(),
            Source::Registry {
                url: "https://registry.npmjs.org".into()
            }
        );
    }

    #[test]
    fn parse_registry_lpm() {
        assert_eq!(
            Source::parse("registry+https://lpm.dev").unwrap(),
            Source::Registry {
                url: "https://lpm.dev".into()
            }
        );
    }

    #[test]
    fn parse_registry_localhost_http() {
        // localhost http is allowed by the existing is_safe_source
        // contract; Source::parse is shape-only and doesn't enforce
        // scheme policy — that's a higher-layer concern.
        assert_eq!(
            Source::parse("registry+http://localhost:3000").unwrap(),
            Source::Registry {
                url: "http://localhost:3000".into()
            }
        );
    }

    // ── Tarball ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_tarball_https() {
        assert_eq!(
            Source::parse("tarball+https://example.com/foo-1.0.0.tgz").unwrap(),
            Source::Tarball {
                url: "https://example.com/foo-1.0.0.tgz".into()
            }
        );
    }

    #[test]
    fn parse_tarball_local_path() {
        assert_eq!(
            Source::parse("tarball+./local/foo.tgz").unwrap(),
            Source::Tarball {
                url: "./local/foo.tgz".into()
            }
        );
    }

    // ── Directory + Link ─────────────────────────────────────────────────────

    #[test]
    fn parse_directory() {
        assert_eq!(
            Source::parse("directory+../packages/foo").unwrap(),
            Source::Directory {
                path: "../packages/foo".into()
            }
        );
    }

    #[test]
    fn parse_link() {
        assert_eq!(
            Source::parse("link+../packages/foo").unwrap(),
            Source::Link {
                path: "../packages/foo".into()
            }
        );
    }

    // ── Git (URL retains the `git+` prefix) ──────────────────────────────────

    #[test]
    fn parse_git_https() {
        assert_eq!(
            Source::parse("git+https://github.com/foo/bar.git").unwrap(),
            Source::Git {
                url: "git+https://github.com/foo/bar.git".into()
            }
        );
    }

    #[test]
    fn parse_git_ssh() {
        assert_eq!(
            Source::parse("git+ssh://git@github.com:foo/bar.git").unwrap(),
            Source::Git {
                url: "git+ssh://git@github.com:foo/bar.git".into()
            }
        );
    }

    // ── Errors ───────────────────────────────────────────────────────────────

    #[test]
    fn parse_empty_returns_error() {
        assert_eq!(Source::parse(""), Err(SourceParseError::Empty));
    }

    #[test]
    fn parse_unknown_kind_with_plus() {
        assert_eq!(
            Source::parse("ftp+ftp://example.com"),
            Err(SourceParseError::UnknownKind("ftp".into()))
        );
    }

    #[test]
    fn parse_no_prefix_returns_unknown_kind() {
        // Bare URLs are NOT recognized — the lockfile always uses
        // discriminator+value form. The error includes the whole
        // typed value (no '+') so the user sees what they wrote.
        assert_eq!(
            Source::parse("https://example.com"),
            Err(SourceParseError::UnknownKind("https://example.com".into()))
        );
    }

    #[test]
    fn parse_registry_empty_value() {
        assert_eq!(
            Source::parse("registry+"),
            Err(SourceParseError::EmptyValue {
                kind: "registry".into()
            })
        );
    }

    #[test]
    fn parse_tarball_empty_value() {
        assert_eq!(
            Source::parse("tarball+"),
            Err(SourceParseError::EmptyValue {
                kind: "tarball".into()
            })
        );
    }

    #[test]
    fn parse_directory_empty_value() {
        assert_eq!(
            Source::parse("directory+"),
            Err(SourceParseError::EmptyValue {
                kind: "directory".into()
            })
        );
    }

    #[test]
    fn parse_link_empty_value() {
        assert_eq!(
            Source::parse("link+"),
            Err(SourceParseError::EmptyValue {
                kind: "link".into()
            })
        );
    }

    #[test]
    fn parse_git_empty_value() {
        // `git+` alone with nothing after is invalid — the URL body
        // is required.
        assert_eq!(
            Source::parse("git+"),
            Err(SourceParseError::EmptyValue { kind: "git".into() })
        );
    }

    // ── Display ──────────────────────────────────────────────────────────────

    #[test]
    fn display_registry() {
        assert_eq!(
            Source::Registry {
                url: "https://registry.npmjs.org".into()
            }
            .to_string(),
            "registry+https://registry.npmjs.org"
        );
    }

    #[test]
    fn display_tarball() {
        assert_eq!(
            Source::Tarball {
                url: "https://e.com/foo.tgz".into()
            }
            .to_string(),
            "tarball+https://e.com/foo.tgz"
        );
    }

    #[test]
    fn display_directory() {
        assert_eq!(
            Source::Directory {
                path: "../packages/foo".into()
            }
            .to_string(),
            "directory+../packages/foo"
        );
    }

    #[test]
    fn display_link() {
        assert_eq!(
            Source::Link {
                path: "../packages/foo".into()
            }
            .to_string(),
            "link+../packages/foo"
        );
    }

    #[test]
    fn display_git() {
        // Git's stored URL already starts with `git+`, so Display is
        // pass-through. This test exists to lock the contract — a
        // future refactor that inserts a second `git+` prefix would
        // fail here.
        assert_eq!(
            Source::Git {
                url: "git+https://github.com/foo/bar.git".into()
            }
            .to_string(),
            "git+https://github.com/foo/bar.git"
        );
    }

    // ── Round-trip (parse → Display → parse must be identity) ────────────────

    fn round_trip(s: &str) {
        let parsed = Source::parse(s).expect("parse");
        let serialized = parsed.to_string();
        assert_eq!(serialized, s, "round-trip mismatch");
        let reparsed = Source::parse(&serialized).expect("reparse");
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn round_trip_registry() {
        round_trip("registry+https://registry.npmjs.org");
        round_trip("registry+https://lpm.dev");
        round_trip("registry+http://localhost:3000");
        round_trip("registry+http://127.0.0.1:8080");
    }

    #[test]
    fn round_trip_tarball() {
        round_trip("tarball+https://example.com/foo-1.0.0.tgz");
        round_trip("tarball+./local/foo.tgz");
        round_trip("tarball+../sibling/foo-2.0.0.tar.gz");
    }

    #[test]
    fn round_trip_directory() {
        round_trip("directory+../packages/foo");
        round_trip("directory+./local/pkg");
    }

    #[test]
    fn round_trip_link() {
        round_trip("link+../packages/foo");
        round_trip("link+./local/pkg");
    }

    #[test]
    fn round_trip_git() {
        round_trip("git+https://github.com/foo/bar.git");
        round_trip("git+ssh://git@github.com:foo/bar.git");
        round_trip("git+git://github.com/foo/bar.git");
    }

    // ── Source::source_id ─────────────────────────────────────────────────────

    #[test]
    fn source_id_registry_keyed_by_url() {
        // Registry source IDs hash the registry URL so cross-registry
        // coexistence of the same (name, version) doesn't collapse
        // identity. Same URL → same id; different URLs → different ids.
        let npmjs = Source::Registry {
            url: "https://registry.npmjs.org".into(),
        }
        .source_id();
        let lpm = Source::Registry {
            url: "https://lpm.dev".into(),
        }
        .source_id();
        let internal = Source::Registry {
            url: "https://npm.internal.example".into(),
        }
        .source_id();

        assert!(npmjs.starts_with("npm-"));
        assert_eq!(npmjs.len(), 4 + 16, "npm- prefix + 16 hex chars");
        assert!(npmjs[4..].chars().all(|c| c.is_ascii_hexdigit()));

        // Distinct registries → distinct ids (the whole point).
        assert_ne!(npmjs, lpm);
        assert_ne!(npmjs, internal);
        assert_ne!(lpm, internal);

        // Same URL → same id (stability).
        let npmjs2 = Source::Registry {
            url: "https://registry.npmjs.org".into(),
        }
        .source_id();
        assert_eq!(npmjs, npmjs2);
    }

    #[test]
    fn source_id_tarball_has_t_prefix_and_16_hex() {
        let id = Source::Tarball {
            url: "https://example.com/foo-1.0.0.tgz".into(),
        }
        .source_id();
        assert!(id.starts_with("t-"), "got {id:?}");
        assert_eq!(id.len(), 18, "t- prefix + 16 hex chars; got {id:?}");
        assert!(id[2..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn source_id_directory_has_f_prefix() {
        let id = Source::Directory {
            path: "../packages/foo".into(),
        }
        .source_id();
        assert!(id.starts_with("f-"), "got {id:?}");
        assert_eq!(id.len(), 18);
    }

    #[test]
    fn source_id_link_has_l_prefix() {
        let id = Source::Link {
            path: "../packages/foo".into(),
        }
        .source_id();
        assert!(id.starts_with("l-"), "got {id:?}");
        assert_eq!(id.len(), 18);
    }

    #[test]
    fn source_id_git_has_g_prefix() {
        let id = Source::Git {
            url: "git+https://github.com/foo/bar.git".into(),
        }
        .source_id();
        assert!(id.starts_with("g-"), "got {id:?}");
        assert_eq!(id.len(), 18);
    }

    #[test]
    fn source_id_is_stable() {
        // Same input → same output, every time.
        let s = Source::Tarball {
            url: "https://e.com/foo.tgz".into(),
        };
        let id1 = s.source_id();
        let id2 = s.source_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn source_id_is_distinct_per_url() {
        let a = Source::Tarball {
            url: "https://e.com/foo.tgz".into(),
        }
        .source_id();
        let b = Source::Tarball {
            url: "https://e.com/bar.tgz".into(),
        }
        .source_id();
        assert_ne!(a, b, "different URLs must produce different source IDs");
    }

    #[test]
    fn source_id_is_distinct_across_kinds_for_same_string() {
        // Even when Tarball and Directory share the same canonical
        // body string (rare but possible), the prefix disambiguates.
        let path = "../packages/foo";
        let dir = Source::Directory { path: path.into() }.source_id();
        let link = Source::Link { path: path.into() }.source_id();
        assert_ne!(dir, link, "f- and l- prefixes must differentiate");
        assert_eq!(&dir[2..], &link[2..], "hash bodies are equal (same input)");
    }

    #[test]
    fn source_id_distinguishes_git_urls() {
        let a = Source::Git {
            url: "git+https://github.com/foo/bar.git".into(),
        }
        .source_id();
        let b = Source::Git {
            url: "git+https://github.com/foo/baz.git".into(),
        }
        .source_id();
        assert_ne!(a, b);
    }

    #[test]
    fn source_id_short_enough_for_lockfile_key_inline() {
        // Hard upper bound: every source_id must be ≤ 20 chars so
        // a lockfile key like `name@version+source-id` stays
        // human-readable in `lpm.lock` diffs.
        let cases = [
            Source::Registry {
                url: "https://registry.npmjs.org".into(),
            },
            Source::Tarball {
                url: "https://example.com/x".into(),
            },
            Source::Directory {
                path: "../x".into(),
            },
            Source::Link {
                path: "../x".into(),
            },
            Source::Git {
                url: "git+https://github.com/x/y.git".into(),
            },
        ];
        for s in cases {
            let id = s.source_id();
            assert!(
                id.len() <= 20,
                "source_id too long for inline key: {id:?} ({} chars)",
                id.len()
            );
        }
    }
}
