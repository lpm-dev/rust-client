//! Explain API: structured "why is this package in the result set" traces.
//!
//! Used by `lpm filter --explain` and the future MCP `lpm_filter_preview` tool
//! (Phase 9). Empty selections still return a `FilterExplain` with a diagnostic
//! trace — they are NOT errors. Per design decision D3, only the explicit
//! `--fail-if-no-match` flag escalates an empty result to a hard error.

use super::{FilterExpr, PackageId};

/// Top-level explain result. Contains the inputs (raw and parsed), the
/// resulting package ID set, and a per-package trace explaining why each
/// member was selected.
#[derive(Debug, Clone)]
pub struct FilterExplain {
    /// Raw filter strings as supplied on the CLI, in order.
    pub input: Vec<String>,
    /// Parsed AST for each input. `parsed.len() == input.len()` always.
    pub parsed: Vec<FilterExpr>,
    /// Selected package IDs in topological execution order.
    pub selected: Vec<PackageId>,
    /// Per-package selection traces. Each entry explains why one
    /// `PackageId` ended up in `selected`. Multiple traces can exist
    /// for the same package if multiple filters matched it.
    pub traces: Vec<SelectionTrace>,
    /// Diagnostic notes — populated when the result set is empty,
    /// when filters were dropped by exclusion, etc.
    pub notes: Vec<String>,
}

/// A single trace anchor: one filter caused one package to be selected,
/// either directly or via a closure operator.
#[derive(Debug, Clone)]
pub struct SelectionTrace {
    /// The package this trace describes.
    pub package: PackageId,
    /// Why the package was selected.
    pub reason: TraceReason,
}

/// The mechanism by which a package was selected.
#[derive(Debug, Clone)]
pub enum TraceReason {
    /// The filter matched this package directly (atom match).
    DirectMatch {
        /// A short human label for the matched filter (e.g. `"@ui/*"`,
        /// `"./apps/web"`).
        filter: String,
        /// The kind of match (exact name, glob, path, etc.).
        kind: MatchKind,
    },
    /// A closure operator (`foo...` or `foo^...`) added this package because
    /// it is a transitive dependency of one of the closure's seeds.
    ViaDependency {
        /// The seed package this dependency was reached from, if exactly one
        /// base in the closure traces back to it. `None` when the closure had
        /// multiple seeds matching this dependency, in which case the explain
        /// renderer should fall back to the filter string.
        of: Option<PackageId>,
        /// A short human label for the closure filter (e.g. `"foo..."`).
        filter: String,
    },
    /// A reverse closure operator (`...foo` or `...^foo`) added this package
    /// because it is a transitive dependent of one of the closure's seeds.
    ViaDependent {
        /// The seed package whose dependent this is, if exactly one base
        /// traces back. See `ViaDependency::of` for the multi-base case.
        of: Option<PackageId>,
        /// A short human label for the closure filter.
        filter: String,
    },
}

/// The kind of atom that produced a `DirectMatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// `foo` — exact name match.
    ExactName,
    /// `@scope/*` — glob over package names.
    GlobName,
    /// `./packages/**` — glob over directory paths.
    PathGlob,
    /// `{./apps/web}` — exact directory match.
    PathExact,
    /// `[origin/main]` — git-ref direct change set.
    GitRef,
}
