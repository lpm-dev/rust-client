//! Phase 32 shared filter engine.
//!
//! Workspace package selection logic shared by every command that accepts
//! `--filter`. Built as a module inside `lpm-task` rather than as a new
//! crate, so it can compose directly with `WorkspaceGraph` and the
//! existing `affected` git plumbing without circular dependencies.
//!
//! ## Architecture (see design doc 37-rust-client-RUNNER-VISION-phase32-filter-engine-design.md)
//!
//! 1. **Parser** (`parser.rs`) — string → `FilterExpr` AST
//! 2. **AST** (`ast.rs`) — the shape the parser produces
//! 3. **Evaluator** (`eval.rs`) — `FilterExpr` + `WorkspaceGraph` → `Vec<PackageId>`
//! 4. **Explain** (`explain.rs`) — structured selection traces for `--explain` mode
//!
//! ## Public surface
//!
//! - [`FilterEngine`] — the central API; constructs once per CLI invocation
//! - [`FilterExpr`] — parsed expression AST
//! - [`parse`] — convenience entry point for `string → FilterExpr`
//! - [`FilterError`] / [`ParseError`] — error types
//! - [`FilterExplain`] / [`SelectionTrace`] / [`TraceReason`] / [`MatchKind`] — explain types
//! - [`PackageId`] — the identifier type used throughout (alias for `usize`)

pub mod ast;
pub mod eval;
pub mod explain;
pub mod parser;

pub use ast::FilterExpr;
pub use explain::{FilterExplain, MatchKind, SelectionTrace, TraceReason};
pub use parser::{ParseError, parse};

use crate::graph::WorkspaceGraph;
use std::path::Path;

/// Identifier type for packages within the filter engine.
///
/// Aliased to `usize` because the existing [`WorkspaceGraph`] already treats
/// indexes as first-class identifiers throughout `topological_sort`,
/// `topological_levels`, `transitive_dependents`, `transitive_dependencies`,
/// and `find_affected*`. Wrapping in a newtype would force a migration of
/// all those callers for no functional gain.
pub type PackageId = usize;

/// Top-level error type for filter operations.
///
/// Parser errors are wrapped via `From<ParseError>` so the engine's evaluate
/// function can accept either a `Vec<FilterExpr>` or a list of strings without
/// caller-side error mapping.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("no filters provided")]
    NoFilters,

    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("invalid glob pattern {pattern:?}: {reason}")]
    InvalidGlob { pattern: String, reason: String },

    #[error("invalid path filter {path:?}: {reason}")]
    InvalidPath { path: String, reason: String },

    #[error("path filter {0:?} escapes workspace root")]
    PathEscape(String),

    #[error("git error: {0}")]
    GitError(String),

    #[error("exclusion requires at least one positive filter")]
    ExclusionOnly,

    /// Only emitted when `--fail-if-no-match` is set; otherwise an empty
    /// result set is just a warning. Per design decision D3 there is no
    /// hidden environment variable that auto-enables this; the flag is
    /// strictly opt-in.
    #[error("no packages matched filter set")]
    NoMatch,
}

/// The shared filter engine. Constructed once per CLI invocation, holds
/// borrows of the workspace graph and the workspace root path. All evaluation
/// methods take `&self` and are pure with respect to the borrowed state.
///
/// The engine is intentionally cheap to construct: it just stores two
/// references. The expensive precomputed adjacency maps live in
/// [`WorkspaceGraph`], which is built upstream by `lpm-cli` and shared.
pub struct FilterEngine<'a> {
    pub(crate) graph: &'a WorkspaceGraph,
    pub(crate) workspace_root: &'a Path,
}

impl<'a> FilterEngine<'a> {
    /// Construct a new filter engine borrowing the given workspace.
    ///
    /// O(1) — just holds references. The graph is expected to already be
    /// built; the engine does not own or rebuild it.
    pub fn new(graph: &'a WorkspaceGraph, workspace_root: &'a Path) -> Self {
        FilterEngine {
            graph,
            workspace_root,
        }
    }

    /// Parse a single filter expression string. Convenience wrapper around
    /// the free-standing [`parse`] function — kept on the engine type for
    /// API discoverability and consistency with `evaluate` / `explain`.
    pub fn parse(input: &str) -> Result<FilterExpr, ParseError> {
        parser::parse(input)
    }
}
