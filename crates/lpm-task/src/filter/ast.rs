//! Filter expression AST.
//!
//! Each variant corresponds to one production in the grammar (see
//! `parser.rs` for the EBNF). The AST is the boundary between parsing
//! and evaluation: the parser produces these, the evaluator consumes them.
//!
//! Invariants enforced by the parser:
//! - `Exclude` only appears at the top level (never nested inside closures)
//! - Closure operators wrap atoms only (never other closures)
//! - All variants are immutable once constructed

/// A parsed filter expression. Multiple filters at the top level UNION
/// (OR) together for positive expressions; `Exclude` variants subtract
/// from the union after evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterExpr {
    /// Exact package name match: `foo`, `@scope/foo`.
    ///
    /// Per design decision D2: strict exact match only. Does NOT match
    /// `@scope/foo` when written as `foo`. Users needing broader matches
    /// must write explicit globs (`*/foo`, `foo-*`).
    ExactName(String),

    /// Glob over package names: `@babel/*`, `foo-*`, `*-test`.
    /// Compiled via the `globset` crate at evaluation time.
    GlobName(String),

    /// Single directory match: `{./apps/web}` (no recursion, just that dir).
    /// The path is canonicalized against workspace root before matching.
    PathExact(String),

    /// Directory glob relative to workspace root: `./packages/**`, `./apps/*`.
    /// Canonicalized literal prefix; the glob suffix matches member paths.
    PathGlob(String),

    /// Changed-since-git-ref atom: `[origin/main]`, `[HEAD~5]`.
    ///
    /// Per design decision D1: returns DIRECTLY changed packages only,
    /// not their transitive dependents. Use the `WithDependents` closure
    /// (`...[main]`) to add dependents explicitly.
    GitRef(String),

    /// Forward closure with seed: `foo...` — `foo` plus everything `foo`
    /// transitively depends on.
    WithDeps(Box<FilterExpr>),

    /// Forward closure without seed: `foo^...` — everything `foo` transitively
    /// depends on, EXCLUDING `foo` itself.
    DepsOnly(Box<FilterExpr>),

    /// Reverse closure with seed: `...foo` — `foo` plus every package that
    /// transitively depends on `foo`.
    WithDependents(Box<FilterExpr>),

    /// Reverse closure without seed: `...^foo` — every package that transitively
    /// depends on `foo`, EXCLUDING `foo` itself.
    DependentsOnly(Box<FilterExpr>),

    /// Top-level exclusion: `!foo`. The inner expression is evaluated normally,
    /// then its result is subtracted from the union of positive filters.
    /// Parser rejects nested or non-top-level exclusions.
    Exclude(Box<FilterExpr>),
}

impl FilterExpr {
    /// Returns true if this expression is an `Exclude` variant.
    /// Used by the top-level evaluator to partition expressions into
    /// positive (UNION) and negative (subtract) groups.
    pub fn is_exclude(&self) -> bool {
        matches!(self, FilterExpr::Exclude(_))
    }
}
