//! Package identity types for the resolver.
//!
//! PubGrub needs `P: Clone + Eq + Hash + Debug + Display`.
//!
//! For Phase 2 (flat resolution), we use simple package names.
//! For future multi-version support, we'll extend with installation context.

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
        /// Format: the parent package name that required this specific version.
        context: Option<String>,
    },

    /// An npm package: `react`, `@types/node`, etc.
    Npm {
        /// Full npm package name (may include scope).
        name: String,
        /// If set, this is a split identity for multi-version resolution.
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
        if name.starts_with("@lpm.dev/") {
            let rest = &name["@lpm.dev/".len()..];
            if let Some(dot_pos) = rest.find('.') {
                return ResolverPackage::Lpm {
                    owner: rest[..dot_pos].to_string(),
                    name: rest[dot_pos + 1..].to_string(),
                    context: None,
                };
            }
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
}
