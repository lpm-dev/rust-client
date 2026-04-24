//! Package identity types for the resolver.
//!
//! PubGrub needs `P: Clone + Eq + Hash + Debug + Display`.
//!
//! Flat resolution uses simple package names.
//! Split retries add installation context so multi-version subtrees can coexist.

use std::fmt;

/// Package identity in the dependency resolver.
///
/// When `context` is None, this is a flat (shared) package — one version for everyone.
/// When `context` is Some, this is a split package — a specific version scoped to
/// the parent that required it. PubGrub treats these as separate packages.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ResolverPackage {
    /// The root project being resolved.
    Root,

    /// An LPM package: `@lpm.dev/owner.name`
    Lpm {
        owner: String,
        name: String,
        /// If set, this is a split identity for multi-version resolution.
        /// Format: the parent's full Display identity (e.g. `"ajv"` for a
        /// flat parent or `"ajv[eslint]"` for an already-split parent).
        /// Using the full identity propagates splits downward so
        /// grandchildren of sibling splits stay distinct. See
        /// `provider.rs` Phase 40 P4 comment for the rationale.
        context: Option<String>,
    },

    /// An npm package: `react`, `@types/node`, etc.
    Npm {
        /// Full npm package name (may include scope).
        name: String,
        /// If set, this is a split identity for multi-version resolution.
        /// Format: the parent's full Display identity (e.g. `"ajv"` for a
        /// flat parent or `"ajv[eslint]"` for an already-split parent).
        /// Using the full identity propagates splits downward so
        /// grandchildren of sibling splits stay distinct. See
        /// `provider.rs` Phase 40 P4 comment for the rationale.
        context: Option<String>,
    },
}

impl ResolverPackage {
    /// Create an LPM package identifier.
    pub fn lpm(owner: &str, name: &str) -> Self {
        ResolverPackage::Lpm {
            owner: owner.to_string(),
            name: name.to_string(),
            context: None,
        }
    }

    /// Create an npm package identifier.
    pub fn npm(name: &str) -> Self {
        ResolverPackage::Npm {
            name: name.to_string(),
            context: None,
        }
    }

    /// Parse a dependency name from package.json into a ResolverPackage.
    ///
    /// `@lpm.dev/owner.name` → `Lpm { owner, name }`
    /// `react` or `@types/node` → `Npm { name }`
    pub fn from_dep_name(name: &str) -> Self {
        if let Some(rest) = name.strip_prefix("@lpm.dev/")
            && let Some(dot_pos) = rest.find('.')
        {
            return ResolverPackage::Lpm {
                owner: rest[..dot_pos].to_string(),
                name: rest[dot_pos + 1..].to_string(),
                context: None,
            };
        }
        ResolverPackage::Npm {
            name: name.to_string(),
            context: None,
        }
    }

    /// Create a context-scoped copy of this package for multi-version splitting.
    /// `ms` with context `"debug"` becomes a separate package from `ms` with context `"send"`.
    pub fn with_context(&self, ctx: &str) -> Self {
        match self {
            ResolverPackage::Root => ResolverPackage::Root,
            ResolverPackage::Lpm { owner, name, .. } => ResolverPackage::Lpm {
                owner: owner.clone(),
                name: name.clone(),
                context: Some(ctx.to_string()),
            },
            ResolverPackage::Npm { name, .. } => ResolverPackage::Npm {
                name: name.clone(),
                context: Some(ctx.to_string()),
            },
        }
    }

    /// Get the canonical package name (without context).
    pub fn canonical_name(&self) -> String {
        match self {
            ResolverPackage::Root => "<root>".to_string(),
            ResolverPackage::Lpm { owner, name, .. } => format!("@lpm.dev/{owner}.{name}"),
            ResolverPackage::Npm { name, .. } => name.clone(),
        }
    }

    /// Get the split context, if this package was scoped for multi-version resolution.
    pub fn context(&self) -> Option<&str> {
        match self {
            ResolverPackage::Root => None,
            ResolverPackage::Lpm { context, .. } => context.as_deref(),
            ResolverPackage::Npm { context, .. } => context.as_deref(),
        }
    }

    /// Whether this is the root package.
    pub fn is_root(&self) -> bool {
        matches!(self, ResolverPackage::Root)
    }

    /// Whether this is an LPM package (fetched from LPM registry).
    pub fn is_lpm(&self) -> bool {
        matches!(self, ResolverPackage::Lpm { .. })
    }

    /// Whether this is an npm package (fetched from npm registry or upstream proxy).
    pub fn is_npm(&self) -> bool {
        matches!(self, ResolverPackage::Npm { .. })
    }

    /// Whether this is a context-split (duplicate) package.
    pub fn is_split(&self) -> bool {
        match self {
            ResolverPackage::Root => false,
            ResolverPackage::Lpm { context, .. } => context.is_some(),
            ResolverPackage::Npm { context, .. } => context.is_some(),
        }
    }
}

/// Canonical, context-free identity of a package.
///
/// **This is the load-bearing key for Phase 49's shared metadata cache.**
/// Unlike [`ResolverPackage`], `CanonicalKey` has NO `context` field, so
/// `lodash` and `lodash[foo]` (a split retry of the same canonical package)
/// map to the same `CanonicalKey`.
///
/// ## Why this exists
///
/// The Phase 49 streaming BFS walker discovers packages by parsing manifest
/// `dependencies` maps — it only ever sees canonical names, never split
/// identities. If the shared cache or notify map were keyed by
/// `ResolverPackage` directly, split retries (`ResolverPackage::with_context`)
/// would produce distinct `Hash + Eq` identities from the walker's canonical
/// inserts, causing silent notify-miss + escape-hatch fetches on exactly the
/// split paths the resolver is designed to preserve.
///
/// Provider code **MUST** canonicalize (`CanonicalKey::from(&pkg)`) before
/// any cache read, notify lookup, or insert. Do not revert this type to
/// include a context field without re-benching and extending the split-
/// subtree regression test in `provider.rs`.
///
/// See `DOCS/new-features/37-rust-client-RUNNER-VISION-phase49-streaming-
/// resolver-preplan.md` §4.2 invariant.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CanonicalKey {
    /// The root project being resolved.
    Root,

    /// An LPM package: `@lpm.dev/owner.name`
    Lpm { owner: String, name: String },

    /// An npm package: `react`, `@types/node`, etc.
    Npm { name: String },
}

impl From<&ResolverPackage> for CanonicalKey {
    /// Strip split context from a `ResolverPackage` to produce its canonical
    /// cache key. This is the ONLY way to construct a `CanonicalKey` from a
    /// resolver-side identity, and is the boundary that enforces
    /// context-free cache keying.
    fn from(pkg: &ResolverPackage) -> Self {
        match pkg {
            ResolverPackage::Root => CanonicalKey::Root,
            ResolverPackage::Lpm { owner, name, .. } => CanonicalKey::Lpm {
                owner: owner.clone(),
                name: name.clone(),
            },
            ResolverPackage::Npm { name, .. } => CanonicalKey::Npm { name: name.clone() },
        }
    }
}

impl CanonicalKey {
    /// Construct an Lpm canonical key.
    pub fn lpm(owner: &str, name: &str) -> Self {
        CanonicalKey::Lpm {
            owner: owner.to_string(),
            name: name.to_string(),
        }
    }

    /// Construct an Npm canonical key.
    pub fn npm(name: &str) -> Self {
        CanonicalKey::Npm {
            name: name.to_string(),
        }
    }

    /// Parse a dependency-map name (`@lpm.dev/owner.name` or `react`) into
    /// a canonical key. Mirrors [`ResolverPackage::from_dep_name`] but
    /// returns the context-free form — used by the BFS walker when it
    /// discovers new dependencies from parsed manifests.
    pub fn from_dep_name(name: &str) -> Self {
        if let Some(rest) = name.strip_prefix("@lpm.dev/")
            && let Some(dot_pos) = rest.find('.')
        {
            return CanonicalKey::Lpm {
                owner: rest[..dot_pos].to_string(),
                name: rest[dot_pos + 1..].to_string(),
            };
        }
        CanonicalKey::Npm {
            name: name.to_string(),
        }
    }
}

impl fmt::Display for CanonicalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalKey::Root => write!(f, "<root>"),
            CanonicalKey::Lpm { owner, name } => write!(f, "@lpm.dev/{owner}.{name}"),
            CanonicalKey::Npm { name } => write!(f, "{name}"),
        }
    }
}

impl fmt::Display for ResolverPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolverPackage::Root => write!(f, "<root>"),
            ResolverPackage::Lpm {
                owner,
                name,
                context: None,
            } => write!(f, "@lpm.dev/{owner}.{name}"),
            ResolverPackage::Lpm {
                owner,
                name,
                context: Some(ctx),
            } => write!(f, "@lpm.dev/{owner}.{name}[{ctx}]"),
            ResolverPackage::Npm {
                name,
                context: None,
            } => write!(f, "{name}"),
            ResolverPackage::Npm {
                name,
                context: Some(ctx),
            } => write!(f, "{name}[{ctx}]"),
        }
    }
}

// PubGrub's `Package` trait is auto-implemented for types satisfying
// Clone + Eq + Hash + Debug + Display — our ResolverPackage satisfies all of these.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_lpm_dep_name() {
        let pkg = ResolverPackage::from_dep_name("@lpm.dev/neo.highlight");
        assert!(pkg.is_lpm());
        assert_eq!(pkg.to_string(), "@lpm.dev/neo.highlight");
    }

    #[test]
    fn from_npm_dep_name() {
        let pkg = ResolverPackage::from_dep_name("react");
        assert!(pkg.is_npm());
        assert_eq!(pkg.to_string(), "react");
    }

    #[test]
    fn from_scoped_npm_dep_name() {
        let pkg = ResolverPackage::from_dep_name("@types/node");
        assert!(pkg.is_npm());
        assert_eq!(pkg.to_string(), "@types/node");
    }

    #[test]
    fn root_display() {
        assert_eq!(ResolverPackage::Root.to_string(), "<root>");
    }

    // --- CanonicalKey (Phase 49) ---

    #[test]
    fn canonical_key_strips_context_from_npm() {
        let flat = ResolverPackage::npm("lodash");
        let split = flat.with_context("debug");
        // Sanity: the two ResolverPackages are distinct Hash+Eq identities.
        assert_ne!(flat, split);
        // But their CanonicalKeys collapse to the same identity.
        assert_eq!(CanonicalKey::from(&flat), CanonicalKey::from(&split));
    }

    #[test]
    fn canonical_key_strips_context_from_lpm() {
        let flat = ResolverPackage::lpm("acme", "util");
        let split = flat.with_context("parent");
        assert_eq!(CanonicalKey::from(&flat), CanonicalKey::from(&split));
    }

    #[test]
    fn canonical_key_preserves_npm_vs_lpm_domain() {
        // An Lpm and an Npm package with coincidentally-similar names must
        // remain distinct canonical keys — the enum variant IS the domain.
        let npm = ResolverPackage::npm("acme");
        let lpm = ResolverPackage::lpm("acme", "acme");
        assert_ne!(CanonicalKey::from(&npm), CanonicalKey::from(&lpm));
    }

    #[test]
    fn canonical_key_from_dep_name_matches_resolver_package_parse() {
        // The walker uses CanonicalKey::from_dep_name; the provider goes
        // through ResolverPackage::from_dep_name. Both must produce
        // matching canonical keys for the same input.
        for name in ["react", "@types/node", "@lpm.dev/neo.highlight", "lodash"] {
            let via_walker = CanonicalKey::from_dep_name(name);
            let via_provider = CanonicalKey::from(&ResolverPackage::from_dep_name(name));
            assert_eq!(
                via_walker, via_provider,
                "canonicalization diverged for {name}: walker={via_walker:?}, provider={via_provider:?}"
            );
        }
    }

    #[test]
    fn canonical_key_root_passthrough() {
        assert_eq!(CanonicalKey::from(&ResolverPackage::Root), CanonicalKey::Root);
        assert_eq!(CanonicalKey::Root.to_string(), "<root>");
    }

    #[test]
    fn canonical_key_display_has_no_context_suffix() {
        // Split ResolverPackage displays as `ms[send]`; its CanonicalKey
        // must display as plain `ms` — otherwise the key is implicitly
        // carrying context via its string form.
        let pkg = ResolverPackage::npm("ms").with_context("send");
        assert_eq!(pkg.to_string(), "ms[send]");
        assert_eq!(CanonicalKey::from(&pkg).to_string(), "ms");
    }

    #[test]
    fn canonical_key_scoped_npm_round_trip() {
        let key = CanonicalKey::from_dep_name("@types/node");
        assert_eq!(key, CanonicalKey::npm("@types/node"));
        assert_eq!(key.to_string(), "@types/node");
    }

    #[test]
    fn canonical_key_lpm_round_trip() {
        let key = CanonicalKey::from_dep_name("@lpm.dev/neo.highlight");
        assert_eq!(key, CanonicalKey::lpm("neo", "highlight"));
        assert_eq!(key.to_string(), "@lpm.dev/neo.highlight");
    }

    #[test]
    fn canonical_key_usable_as_hashmap_key() {
        use std::collections::HashMap;
        let mut map: HashMap<CanonicalKey, &'static str> = HashMap::new();
        map.insert(CanonicalKey::npm("lodash"), "flat");
        // A split-context ResolverPackage must hit the SAME entry via its
        // canonical key — this is the boundary test the preplan §4.2 cites.
        let split = ResolverPackage::npm("lodash").with_context("parent");
        assert_eq!(map.get(&CanonicalKey::from(&split)), Some(&"flat"));
    }
}
