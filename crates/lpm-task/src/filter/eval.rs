//! Filter evaluator and supporting types.
//!
//! `PackageBits` is the dense set representation used during evaluation.
//! The evaluator translates `FilterExpr` ASTs into `PackageBits` against
//! a borrowed `WorkspaceGraph`, then `evaluate` produces a deterministic
//! topologically-sorted `Vec<PackageId>` for callers.

use super::explain::{FilterExplain, MatchKind, SelectionTrace, TraceReason};
use super::{FilterEngine, FilterError, FilterExpr, PackageId};
use crate::affected;
use globset::{Glob, GlobMatcher};
use std::path::{Path, PathBuf};

/// Dense bit-set sized to the workspace member count. Used during filter
/// evaluation for cheap set algebra. Returned to callers as
/// `Vec<PackageId>` (sorted, deterministic) via `to_sorted_vec`.
///
/// Implementation: `Vec<bool>` rather than a real bitset crate. The expected
/// workspace size (≤ ~10k members) makes the cache-line locality of `Vec<bool>`
/// preferable to a packed bitset, and we avoid an extra dependency. If
/// benchmarks show cache pressure on large workspaces, swap to `bit-set`.
#[derive(Debug, Clone)]
pub(crate) struct PackageBits(Vec<bool>);

impl PackageBits {
    /// Create an empty bit-set sized to `len` members.
    pub fn empty(len: usize) -> Self {
        PackageBits(vec![false; len])
    }

    /// Create a full bit-set with all `len` members set.
    #[allow(dead_code)] // used by M4 evaluator
    pub fn full(len: usize) -> Self {
        PackageBits(vec![true; len])
    }

    /// Number of underlying slots (NOT the number of set bits).
    /// Used to size companion bitsets and by tests.
    #[allow(dead_code)] // public API surface; used by tests and reserved for callers building companion bitsets
    pub fn capacity(&self) -> usize {
        self.0.len()
    }

    /// Set the bit at `id` to true.
    pub fn set(&mut self, id: PackageId) {
        if id < self.0.len() {
            self.0[id] = true;
        }
    }

    /// Check if `id` is set.
    pub fn contains(&self, id: PackageId) -> bool {
        self.0.get(id).copied().unwrap_or(false)
    }

    /// Number of set bits.
    #[allow(dead_code)] // public API surface; used by tests and useful for external callers measuring filter selectivity
    pub fn count(&self) -> usize {
        self.0.iter().filter(|b| **b).count()
    }

    /// Returns true if no bits are set.
    pub fn is_empty(&self) -> bool {
        !self.0.iter().any(|b| *b)
    }

    /// In-place union: `self = self ∪ other`.
    pub fn union_with(&mut self, other: &PackageBits) {
        let len = self.0.len().min(other.0.len());
        for i in 0..len {
            self.0[i] |= other.0[i];
        }
    }

    /// In-place subtraction: `self = self − other`.
    pub fn subtract(&mut self, other: &PackageBits) {
        let len = self.0.len().min(other.0.len());
        for i in 0..len {
            if other.0[i] {
                self.0[i] = false;
            }
        }
    }

    /// Iterate over the set member IDs in ascending order.
    pub fn iter_ids(&self) -> impl Iterator<Item = PackageId> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, &set)| if set { Some(i) } else { None })
    }

    /// Convert to a sorted `Vec<PackageId>`. Output is deterministic
    /// because we iterate the underlying `Vec<bool>` in order.
    pub fn to_sorted_vec(&self) -> Vec<PackageId> {
        self.iter_ids().collect()
    }
}

// ─── FilterEngine evaluation ─────────────────────────────────────────────

impl<'a> FilterEngine<'a> {
    /// Evaluate a list of parsed filter expressions against the workspace.
    ///
    /// Composition rule (per design doc §8.1):
    ///
    /// ```text
    /// result = (eval(positive_1) ∪ ... ∪ eval(positive_n))
    ///        − (eval(exclude_1)  ∪ ... ∪ eval(exclude_m))
    /// ```
    ///
    /// Output is sorted in topological execution order (dependencies before
    /// dependents) so callers iterating the result get a stable order.
    ///
    /// # Errors
    ///
    /// - [`FilterError::NoFilters`] if `filters` is empty
    /// - [`FilterError::ExclusionOnly`] if every filter is an `Exclude` variant
    ///   (per D3, an exclusion-only list is a user error and not gated by
    ///   `--fail-if-no-match`)
    /// - Any error from atom evaluation (path escape, glob compilation, git)
    pub fn evaluate(&self, filters: &[FilterExpr]) -> Result<Vec<PackageId>, FilterError> {
        if filters.is_empty() {
            return Err(FilterError::NoFilters);
        }
        if filters.iter().all(FilterExpr::is_exclude) {
            return Err(FilterError::ExclusionOnly);
        }

        let len = self.graph.len();
        let mut include = PackageBits::empty(len);
        let mut exclude = PackageBits::empty(len);

        for filter in filters {
            match filter {
                FilterExpr::Exclude(inner) => {
                    let bits = self.eval_expr(inner)?;
                    exclude.union_with(&bits);
                }
                _ => {
                    let bits = self.eval_expr(filter)?;
                    include.union_with(&bits);
                }
            }
        }

        include.subtract(&exclude);
        Ok(self.topologically_sorted(&include))
    }

    /// Evaluate a single (non-`Exclude`) `FilterExpr` into a `PackageBits`.
    /// Recursively dispatches on the variant.
    ///
    /// `Exclude` is handled at the top level by `evaluate` — never reached here.
    pub(crate) fn eval_expr(&self, expr: &FilterExpr) -> Result<PackageBits, FilterError> {
        match expr {
            FilterExpr::ExactName(name) => Ok(self.eval_exact_name(name)),
            FilterExpr::GlobName(pat) => self.eval_glob_name(pat),
            FilterExpr::PathExact(path) => self.eval_path_exact(path),
            FilterExpr::PathGlob(pat) => self.eval_path_glob(pat),
            FilterExpr::GitRef(reff) => self.eval_git_ref(reff),
            FilterExpr::WithDeps(inner) => {
                let base = self.eval_expr(inner)?;
                Ok(self.closure_with_deps(&base))
            }
            FilterExpr::DepsOnly(inner) => {
                let base = self.eval_expr(inner)?;
                let mut closure = self.closure_with_deps(&base);
                closure.subtract(&base);
                Ok(closure)
            }
            FilterExpr::WithDependents(inner) => {
                let base = self.eval_expr(inner)?;
                Ok(self.closure_with_dependents(&base))
            }
            FilterExpr::DependentsOnly(inner) => {
                let base = self.eval_expr(inner)?;
                let mut closure = self.closure_with_dependents(&base);
                closure.subtract(&base);
                Ok(closure)
            }
            FilterExpr::Exclude(_) => {
                // Reachable only if a parser bug allowed nested exclusion.
                // Treat as a programming error rather than panicking.
                Err(FilterError::ExclusionOnly)
            }
        }
    }

    // ── Atom evaluators ───────────────────────────────────────────────────

    /// Per D2: strict exact match. `foo` matches only a package literally
    /// named `foo`. Does NOT match `@scope/foo` or `foo-utils`.
    fn eval_exact_name(&self, name: &str) -> PackageBits {
        let mut bits = PackageBits::empty(self.graph.len());
        if let Some(idx) = self.graph.index_of(name) {
            bits.set(idx);
        }
        bits
    }

    /// Glob over package names using `globset`.
    fn eval_glob_name(&self, pattern: &str) -> Result<PackageBits, FilterError> {
        let matcher = self.get_or_compile_glob(pattern)?;
        let mut bits = PackageBits::empty(self.graph.len());
        for (idx, node) in self.graph.members.iter().enumerate() {
            if matcher.is_match(&node.name) {
                bits.set(idx);
            }
        }
        Ok(bits)
    }

    /// Exact directory match. The path is canonicalized against the
    /// workspace root and verified not to escape it.
    fn eval_path_exact(&self, path: &str) -> Result<PackageBits, FilterError> {
        let canonical = canonicalize_workspace_path(self.workspace_root, path)?;
        let mut bits = PackageBits::empty(self.graph.len());
        for (idx, node) in self.graph.members.iter().enumerate() {
            // Member paths are stored already-canonical at workspace discovery
            // time, so a direct comparison is correct.
            if let Ok(member_canonical) = node.path.canonicalize() {
                if member_canonical == canonical {
                    bits.set(idx);
                }
            } else if node.path == canonical {
                // Fallback for fixtures/tests that use synthetic paths
                bits.set(idx);
            }
        }
        Ok(bits)
    }

    /// Directory glob. The literal prefix is canonicalized against the
    /// workspace root, then `globset` matches the suffix against each
    /// member's relative path.
    fn eval_path_glob(&self, pattern: &str) -> Result<PackageBits, FilterError> {
        // Strip the `./` or `../` prefix and verify the literal portion
        // does not escape the workspace root.
        let (literal_prefix, glob_suffix) = split_glob_pattern(pattern);
        let literal_canonical = canonicalize_workspace_path(self.workspace_root, &literal_prefix)?;

        // Reconstruct the full glob pattern relative to the workspace root
        // for matching against each member.
        let full_pattern = if glob_suffix.is_empty() {
            literal_canonical.to_string_lossy().to_string()
        } else {
            format!("{}/{}", literal_canonical.display(), glob_suffix)
        };
        let matcher = self.get_or_compile_glob(&full_pattern)?;

        let mut bits = PackageBits::empty(self.graph.len());
        for (idx, node) in self.graph.members.iter().enumerate() {
            let path_str = node
                .path
                .canonicalize()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| node.path.to_string_lossy().to_string());
            if matcher.is_match(&path_str) {
                bits.set(idx);
            }
        }
        Ok(bits)
    }

    /// Compile a glob matcher once per engine lifetime and reuse it across
    /// repeated evaluations. This removes `globset` compile overhead from
    /// hot paths like the perf guards, which repeatedly evaluate the same
    /// parsed filter expression against a fixed workspace.
    fn get_or_compile_glob(&self, pattern: &str) -> Result<GlobMatcher, FilterError> {
        if let Some(matcher) = self.glob_cache.borrow().get(pattern) {
            return Ok(matcher.clone());
        }

        let matcher = compile_glob(pattern)?;
        self.glob_cache
            .borrow_mut()
            .insert(pattern.to_string(), matcher.clone());
        Ok(matcher)
    }

    /// Git ref atom. Per D1, returns directly changed packages only —
    /// dependents are added by an enclosing `WithDependents` closure.
    fn eval_git_ref(&self, base_ref: &str) -> Result<PackageBits, FilterError> {
        let affected_set =
            affected::find_affected_direct_only(self.graph, self.workspace_root, base_ref)
                .map_err(FilterError::GitError)?;
        let mut bits = PackageBits::empty(self.graph.len());
        for idx in affected_set {
            bits.set(idx);
        }
        Ok(bits)
    }

    // ── Closure operators ─────────────────────────────────────────────────

    /// Forward closure: union of `base` with the transitive dependencies of
    /// every member in `base`. Used by `foo...` and `foo^...`.
    fn closure_with_deps(&self, base: &PackageBits) -> PackageBits {
        let mut result = base.clone();
        for idx in base.iter_ids() {
            for dep_idx in self.graph.transitive_dependencies(idx) {
                result.set(dep_idx);
            }
        }
        result
    }

    /// Reverse closure: union of `base` with the transitive dependents of
    /// every member in `base`. Used by `...foo` and `...^foo`.
    fn closure_with_dependents(&self, base: &PackageBits) -> PackageBits {
        let mut result = base.clone();
        for idx in base.iter_ids() {
            for dep_idx in self.graph.transitive_dependents(idx) {
                result.set(dep_idx);
            }
        }
        result
    }

    // ── Output ordering ───────────────────────────────────────────────────

    /// Sort the bits into topological execution order (dependencies first).
    /// Falls back to ascending index order if the graph has a cycle (which
    /// `WorkspaceGraph::topological_levels` would surface as `GraphError`).
    fn topologically_sorted(&self, bits: &PackageBits) -> Vec<PackageId> {
        match self.graph.topological_levels() {
            Ok(levels) => levels
                .iter()
                .flat_map(|level| level.iter().filter(|i| bits.contains(**i)).copied())
                .collect(),
            // If the graph has a cycle, fall back to deterministic index order.
            // The error is reported elsewhere (existing graph callers already
            // handle this surface).
            Err(_) => bits.to_sorted_vec(),
        }
    }

    // ── Explain API ───────────────────────────────────────────────────────

    /// Evaluate filters and return a structured explain trace.
    ///
    /// The explain output is intended for `lpm filter --explain` and the
    /// future MCP `lpm_filter_preview` tool. It mirrors `evaluate` exactly
    /// for the package set, then adds per-package traces explaining which
    /// filter contributed each package and how (direct match vs closure).
    ///
    /// Empty result sets are NOT errors here — per D3, only the explicit
    /// `--fail-if-no-match` flag escalates that. Empty results return a
    /// `FilterExplain` with an empty `selected` and a diagnostic in `notes`.
    pub fn explain(&self, filters: &[FilterExpr]) -> Result<FilterExplain, FilterError> {
        if filters.is_empty() {
            return Err(FilterError::NoFilters);
        }
        if filters.iter().all(FilterExpr::is_exclude) {
            return Err(FilterError::ExclusionOnly);
        }

        let len = self.graph.len();
        let mut include = PackageBits::empty(len);
        let mut exclude = PackageBits::empty(len);
        let mut traces: Vec<SelectionTrace> = Vec::new();
        let mut covered = PackageBits::empty(len);

        // Pass 1: positive filters. Track first-attribution traces.
        for filter in filters {
            if filter.is_exclude() {
                continue;
            }
            let bits = self.eval_expr(filter)?;

            // Compute base bits for closure operators so we can distinguish
            // direct matches from closure-expansion adds.
            let base_bits = match filter {
                FilterExpr::WithDeps(inner)
                | FilterExpr::DepsOnly(inner)
                | FilterExpr::WithDependents(inner)
                | FilterExpr::DependentsOnly(inner) => Some(self.eval_expr(inner)?),
                _ => None,
            };

            for id in bits.iter_ids() {
                if covered.contains(id) {
                    continue;
                }
                let reason = self.trace_reason(filter, id, base_bits.as_ref());
                traces.push(SelectionTrace {
                    package: id,
                    reason,
                });
                covered.set(id);
            }
            include.union_with(&bits);
        }

        // Pass 2: exclusions
        for filter in filters {
            if let FilterExpr::Exclude(inner) = filter {
                let bits = self.eval_expr(inner)?;
                exclude.union_with(&bits);
            }
        }

        include.subtract(&exclude);

        // Drop traces for packages excluded after the union step.
        traces.retain(|t| include.contains(t.package));

        let mut notes = Vec::new();
        if include.is_empty() {
            notes.push(
                "Filter set produced no matches. \
                 Use --fail-if-no-match in CI to escalate this to an error."
                    .to_string(),
            );
        }

        Ok(FilterExplain {
            input: Vec::new(), // populated by caller from raw CLI args
            parsed: filters.to_vec(),
            selected: self.topologically_sorted(&include),
            traces,
            notes,
        })
    }

    /// Build a `TraceReason` for a single (package, filter) pair, given the
    /// optional precomputed base bits for closure operators.
    fn trace_reason(
        &self,
        filter: &FilterExpr,
        package: PackageId,
        base_bits: Option<&PackageBits>,
    ) -> TraceReason {
        match filter {
            FilterExpr::ExactName(_)
            | FilterExpr::GlobName(_)
            | FilterExpr::PathExact(_)
            | FilterExpr::PathGlob(_)
            | FilterExpr::GitRef(_) => TraceReason::DirectMatch {
                filter: format_expr(filter),
                kind: match_kind_for(filter),
            },
            FilterExpr::WithDeps(inner) | FilterExpr::DepsOnly(inner) => {
                if let Some(base) = base_bits
                    && base.contains(package)
                {
                    // The package is one of the closure's seeds — direct match.
                    TraceReason::DirectMatch {
                        filter: format_expr(filter),
                        kind: match_kind_for(inner),
                    }
                } else {
                    TraceReason::ViaDependency {
                        of: trace_origin_dep(self, base_bits, package),
                        filter: format_expr(filter),
                    }
                }
            }
            FilterExpr::WithDependents(inner) | FilterExpr::DependentsOnly(inner) => {
                if let Some(base) = base_bits
                    && base.contains(package)
                {
                    TraceReason::DirectMatch {
                        filter: format_expr(filter),
                        kind: match_kind_for(inner),
                    }
                } else {
                    TraceReason::ViaDependent {
                        of: trace_origin_dependent(self, base_bits, package),
                        filter: format_expr(filter),
                    }
                }
            }
            FilterExpr::Exclude(_) => {
                // Reachable only via parser bug; fall back to a placeholder.
                TraceReason::DirectMatch {
                    filter: format_expr(filter),
                    kind: MatchKind::ExactName,
                }
            }
        }
    }
}

/// Find a base package whose `transitive_dependencies` contains `package`.
/// Returns `None` if `base_bits` is `None` or if no single base matches
/// (or if multiple bases match — we don't pick one in that ambiguous case).
fn trace_origin_dep(
    engine: &FilterEngine<'_>,
    base_bits: Option<&PackageBits>,
    package: PackageId,
) -> Option<PackageId> {
    let base = base_bits?;
    let mut matches: Vec<PackageId> = Vec::new();
    for base_id in base.iter_ids() {
        if engine
            .graph
            .transitive_dependencies(base_id)
            .contains(&package)
        {
            matches.push(base_id);
            if matches.len() > 1 {
                return None;
            }
        }
    }
    matches.into_iter().next()
}

/// Symmetric counterpart of `trace_origin_dep` for reverse closures.
fn trace_origin_dependent(
    engine: &FilterEngine<'_>,
    base_bits: Option<&PackageBits>,
    package: PackageId,
) -> Option<PackageId> {
    let base = base_bits?;
    let mut matches: Vec<PackageId> = Vec::new();
    for base_id in base.iter_ids() {
        if engine
            .graph
            .transitive_dependents(base_id)
            .contains(&package)
        {
            matches.push(base_id);
            if matches.len() > 1 {
                return None;
            }
        }
    }
    matches.into_iter().next()
}

/// Render a `FilterExpr` as a short human-readable label, used in
/// `TraceReason::filter` strings. Not a full inverse of the parser —
/// just a label-grade representation.
fn format_expr(expr: &FilterExpr) -> String {
    match expr {
        FilterExpr::ExactName(s) => s.clone(),
        FilterExpr::GlobName(s) => s.clone(),
        FilterExpr::PathExact(p) => format!("{{{p}}}"),
        FilterExpr::PathGlob(p) => p.clone(),
        FilterExpr::GitRef(r) => format!("[{r}]"),
        FilterExpr::WithDeps(inner) => format!("{}...", format_expr(inner)),
        FilterExpr::DepsOnly(inner) => format!("{}^...", format_expr(inner)),
        FilterExpr::WithDependents(inner) => format!("...{}", format_expr(inner)),
        FilterExpr::DependentsOnly(inner) => format!("...^{}", format_expr(inner)),
        FilterExpr::Exclude(inner) => format!("!{}", format_expr(inner)),
    }
}

/// Map a `FilterExpr` atom to its `MatchKind` for explain output. Closures
/// recurse into their inner expression.
fn match_kind_for(expr: &FilterExpr) -> MatchKind {
    match expr {
        FilterExpr::ExactName(_) => MatchKind::ExactName,
        FilterExpr::GlobName(_) => MatchKind::GlobName,
        FilterExpr::PathExact(_) => MatchKind::PathExact,
        FilterExpr::PathGlob(_) => MatchKind::PathGlob,
        FilterExpr::GitRef(_) => MatchKind::GitRef,
        FilterExpr::WithDeps(inner)
        | FilterExpr::DepsOnly(inner)
        | FilterExpr::WithDependents(inner)
        | FilterExpr::DependentsOnly(inner)
        | FilterExpr::Exclude(inner) => match_kind_for(inner),
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Compile a glob pattern via `globset` and return a matcher, mapping any
/// compile error to `FilterError::InvalidGlob`.
fn compile_glob(pattern: &str) -> Result<GlobMatcher, FilterError> {
    Glob::new(pattern)
        .map(|g| g.compile_matcher())
        .map_err(|e| FilterError::InvalidGlob {
            pattern: pattern.to_string(),
            reason: e.to_string(),
        })
}

/// Split a path glob like `./packages/**` into `("packages", "**")`.
/// The literal prefix is the segments BEFORE any glob metacharacter; the
/// suffix is everything after (possibly empty).
fn split_glob_pattern(pattern: &str) -> (String, String) {
    let mut literal = String::new();
    let mut suffix = String::new();
    let mut hit_glob = false;
    for segment in pattern.split('/') {
        if hit_glob || segment.contains('*') || segment.contains('?') || segment.contains('[') {
            hit_glob = true;
            if !suffix.is_empty() {
                suffix.push('/');
            }
            suffix.push_str(segment);
        } else {
            if !literal.is_empty() {
                literal.push('/');
            }
            literal.push_str(segment);
        }
    }
    if literal.is_empty() {
        literal.push('.');
    }
    (literal, suffix)
}

/// Canonicalize a path against the workspace root and verify it does not
/// escape the workspace boundary.
///
/// Three-stage resolution:
///
/// 1. Try `joined.canonicalize()` directly. Works when every component of
///    the joined path exists on disk. Resolves symlinks.
/// 2. Otherwise lexically normalize (collapse `..` and `.` purely
///    syntactically), then try to canonicalize THAT result. This handles
///    inputs like `./packages/foo/../bar` where `foo` doesn't exist but
///    `bar` does.
/// 3. If neither works, use the lexical form as-is. Used by unit tests
///    with fully synthetic fixtures.
///
/// The containment check uses the disk-canonical workspace root whenever
/// possible so symlink resolution (e.g., macOS `/tmp` → `/private/tmp`)
/// produces a consistent comparison.
fn canonicalize_workspace_path(workspace_root: &Path, input: &str) -> Result<PathBuf, FilterError> {
    let joined = workspace_root.join(input);

    // Stage 1: direct canonicalization
    let resolved = if let Ok(p) = joined.canonicalize() {
        p
    } else {
        // Stage 2: lexical normalization, then re-canonicalize
        let lexical = lexical_normalize(&joined);
        lexical.canonicalize().unwrap_or(lexical)
    };

    // Pick the comparison root with matching normalization. If the resolved
    // path is fully canonical (has prefixes like /private/...), the root must
    // be too; otherwise both should be lexical.
    let root_canonical = workspace_root.canonicalize();
    let root_lexical = lexical_normalize(workspace_root);
    let root = match &root_canonical {
        Ok(c) if resolved.starts_with(c) || resolved == *c => c.clone(),
        _ if resolved.starts_with(&root_lexical) || resolved == root_lexical => root_lexical,
        Ok(c) => c.clone(),
        Err(_) => root_lexical,
    };

    if !resolved.starts_with(&root) && resolved != root {
        return Err(FilterError::PathEscape(input.to_string()));
    }

    Ok(resolved)
}

/// Lexical path normalization: resolve `..` and `.` components purely
/// syntactically. Used as a fallback when the path doesn't exist on disk
/// (e.g., in unit tests with synthetic fixtures).
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bits_are_empty() {
        let bits = PackageBits::empty(10);
        assert!(bits.is_empty());
        assert_eq!(bits.count(), 0);
        assert_eq!(bits.capacity(), 10);
    }

    #[test]
    fn full_bits_are_full() {
        let bits = PackageBits::full(5);
        assert!(!bits.is_empty());
        assert_eq!(bits.count(), 5);
        for i in 0..5 {
            assert!(bits.contains(i));
        }
    }

    #[test]
    fn set_and_contains_work() {
        let mut bits = PackageBits::empty(5);
        bits.set(2);
        bits.set(4);
        assert!(bits.contains(2));
        assert!(bits.contains(4));
        assert!(!bits.contains(0));
        assert!(!bits.contains(1));
        assert!(!bits.contains(3));
        assert_eq!(bits.count(), 2);
    }

    #[test]
    fn set_out_of_bounds_is_silent_noop() {
        let mut bits = PackageBits::empty(3);
        bits.set(99);
        assert!(bits.is_empty());
        assert!(!bits.contains(99));
    }

    #[test]
    fn union_combines_two_bitsets() {
        let mut a = PackageBits::empty(5);
        a.set(0);
        a.set(2);
        let mut b = PackageBits::empty(5);
        b.set(2);
        b.set(4);
        a.union_with(&b);
        assert!(a.contains(0));
        assert!(a.contains(2));
        assert!(a.contains(4));
        assert!(!a.contains(1));
        assert!(!a.contains(3));
        assert_eq!(a.count(), 3);
    }

    #[test]
    fn subtract_removes_other_bits() {
        let mut a = PackageBits::empty(5);
        for i in 0..5 {
            a.set(i);
        }
        let mut b = PackageBits::empty(5);
        b.set(1);
        b.set(3);
        a.subtract(&b);
        assert!(a.contains(0));
        assert!(!a.contains(1));
        assert!(a.contains(2));
        assert!(!a.contains(3));
        assert!(a.contains(4));
        assert_eq!(a.count(), 3);
    }

    #[test]
    fn to_sorted_vec_is_deterministic_and_ordered() {
        let mut bits = PackageBits::empty(10);
        bits.set(7);
        bits.set(2);
        bits.set(5);
        bits.set(0);
        let v = bits.to_sorted_vec();
        assert_eq!(v, vec![0, 2, 5, 7]);
    }

    #[test]
    fn iter_ids_returns_in_order() {
        let mut bits = PackageBits::empty(8);
        bits.set(6);
        bits.set(1);
        bits.set(3);
        let collected: Vec<_> = bits.iter_ids().collect();
        assert_eq!(collected, vec![1, 3, 6]);
    }

    // ── Filter engine evaluator tests ──────────────────────────────────────

    use crate::graph::WorkspaceGraph;
    use lpm_workspace::{PackageJson, Workspace, WorkspaceMember};
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// Build a synthetic workspace member with explicit deps.
    fn member(name: &str, deps: &[&str]) -> WorkspaceMember {
        let mut dependencies = HashMap::new();
        for d in deps {
            dependencies.insert((*d).to_string(), "*".to_string());
        }
        WorkspaceMember {
            path: PathBuf::from(format!("/workspace/packages/{name}")),
            package: PackageJson {
                name: Some(name.to_string()),
                dependencies,
                ..Default::default()
            },
        }
    }

    /// Realistic-ish monorepo fixture used by most evaluator tests:
    ///
    /// ```text
    /// apps/web      → packages/auth, packages/ui-button
    /// apps/admin    → packages/auth, packages/ui-card
    /// packages/auth → packages/utils
    /// packages/ui-button → (none)
    /// packages/ui-card   → packages/ui-button
    /// packages/utils → (none)
    /// ```
    ///
    /// Index assignments are stable based on insertion order:
    /// 0 = utils, 1 = ui-button, 2 = ui-card, 3 = auth,
    /// 4 = web, 5 = admin
    fn realistic_workspace() -> Workspace {
        Workspace {
            root: PathBuf::from("/workspace"),
            root_package: PackageJson::default(),
            members: vec![
                member("utils", &[]),
                member("ui-button", &[]),
                member("ui-card", &["ui-button"]),
                member("auth", &["utils"]),
                member("web", &["auth", "ui-button"]),
                member("admin", &["auth", "ui-card"]),
            ],
        }
    }

    /// Construct an engine over a fixture and the corresponding graph.
    /// Returns owned values to keep lifetimes simple in test bodies.
    fn make_engine() -> (Workspace, WorkspaceGraph, PathBuf) {
        let ws = realistic_workspace();
        let graph = WorkspaceGraph::from_workspace(&ws);
        let root = ws.root.clone();
        (ws, graph, root)
    }

    /// Resolve a package name to its index in the realistic fixture.
    fn idx(graph: &WorkspaceGraph, name: &str) -> PackageId {
        graph
            .index_of(name)
            .unwrap_or_else(|| panic!("missing: {name}"))
    }

    // ── Atom evaluators ────────────────────────────────────────────────────

    #[test]
    fn evaluator_exact_name_selects_one_member() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::ExactName("auth".into());

        let result = engine.evaluate(&[expr]).unwrap();
        assert_eq!(result, vec![idx(&graph, "auth")]);
    }

    #[test]
    fn evaluator_exact_name_returns_empty_for_missing() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::ExactName("does-not-exist".into());

        let result = engine.evaluate(&[expr]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn evaluator_exact_name_does_not_match_substring_per_d2() {
        // D2: `core` must NOT match `ui-button`, `ui-card`, etc.
        // The fixture has no package literally named `ui` so an exact `ui`
        // filter must return empty even though `ui-button` and `ui-card` exist.
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::ExactName("ui".into());

        let result = engine.evaluate(&[expr]).unwrap();
        assert!(
            result.is_empty(),
            "exact match must NOT fall back to substring matching (D2)"
        );
    }

    #[test]
    fn evaluator_glob_name_matches_prefix_pattern() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::GlobName("ui-*".into());

        let result = engine.evaluate(&[expr]).unwrap();
        let result_set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(result_set.contains(&idx(&graph, "ui-button")));
        assert!(result_set.contains(&idx(&graph, "ui-card")));
        assert!(!result_set.contains(&idx(&graph, "auth")));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn evaluator_glob_name_invalid_pattern_errors() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        // Unmatched bracket — globset rejects this
        let expr = FilterExpr::GlobName("[broken".into());

        match engine.evaluate(&[expr]) {
            Err(FilterError::InvalidGlob { .. }) => {}
            other => panic!("expected InvalidGlob, got {other:?}"),
        }
    }

    // ── Closure operators ──────────────────────────────────────────────────

    #[test]
    fn evaluator_with_deps_includes_seed_and_transitive_deps() {
        // web → auth → utils, web → ui-button
        // web... = {web, auth, utils, ui-button}
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::WithDeps(Box::new(FilterExpr::ExactName("web".into())));

        let result = engine.evaluate(&[expr]).unwrap();
        let set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(set.contains(&idx(&graph, "web")));
        assert!(set.contains(&idx(&graph, "auth")));
        assert!(set.contains(&idx(&graph, "utils")));
        assert!(set.contains(&idx(&graph, "ui-button")));
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn evaluator_deps_only_excludes_seed() {
        // web^... = {auth, utils, ui-button}  (NOT web itself)
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::DepsOnly(Box::new(FilterExpr::ExactName("web".into())));

        let result = engine.evaluate(&[expr]).unwrap();
        let set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(!set.contains(&idx(&graph, "web")), "seed must be excluded");
        assert!(set.contains(&idx(&graph, "auth")));
        assert!(set.contains(&idx(&graph, "utils")));
        assert!(set.contains(&idx(&graph, "ui-button")));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn evaluator_with_dependents_includes_seed_and_dependents() {
        // utils ← auth ← {web, admin}
        // ...utils = {utils, auth, web, admin}
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::WithDependents(Box::new(FilterExpr::ExactName("utils".into())));

        let result = engine.evaluate(&[expr]).unwrap();
        let set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(set.contains(&idx(&graph, "utils")));
        assert!(set.contains(&idx(&graph, "auth")));
        assert!(set.contains(&idx(&graph, "web")));
        assert!(set.contains(&idx(&graph, "admin")));
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn evaluator_dependents_only_excludes_seed() {
        // ...^utils = {auth, web, admin}  (NOT utils itself)
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::DependentsOnly(Box::new(FilterExpr::ExactName("utils".into())));

        let result = engine.evaluate(&[expr]).unwrap();
        let set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(
            !set.contains(&idx(&graph, "utils")),
            "seed must be excluded"
        );
        assert!(set.contains(&idx(&graph, "auth")));
        assert!(set.contains(&idx(&graph, "web")));
        assert!(set.contains(&idx(&graph, "admin")));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn evaluator_closure_over_glob() {
        // ...(ui-*) = {ui-button, ui-card, web (depends on ui-button), admin (depends on ui-card)}
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let expr = FilterExpr::WithDependents(Box::new(FilterExpr::GlobName("ui-*".into())));

        let result = engine.evaluate(&[expr]).unwrap();
        let set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(set.contains(&idx(&graph, "ui-button")));
        assert!(set.contains(&idx(&graph, "ui-card")));
        assert!(set.contains(&idx(&graph, "web")));
        assert!(set.contains(&idx(&graph, "admin")));
        assert_eq!(set.len(), 4);
    }

    // ── Multi-filter union and exclusion ───────────────────────────────────

    #[test]
    fn evaluator_multi_filter_unions_positive_filters() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![
            FilterExpr::ExactName("auth".into()),
            FilterExpr::ExactName("utils".into()),
        ];

        let result = engine.evaluate(&exprs).unwrap();
        let set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(set.contains(&idx(&graph, "auth")));
        assert!(set.contains(&idx(&graph, "utils")));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn evaluator_exclude_subtracts_from_union() {
        // (ui-* + auth) − ui-card = {ui-button, auth}
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![
            FilterExpr::GlobName("ui-*".into()),
            FilterExpr::ExactName("auth".into()),
            FilterExpr::Exclude(Box::new(FilterExpr::ExactName("ui-card".into()))),
        ];

        let result = engine.evaluate(&exprs).unwrap();
        let set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(set.contains(&idx(&graph, "ui-button")));
        assert!(set.contains(&idx(&graph, "auth")));
        assert!(!set.contains(&idx(&graph, "ui-card")));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn evaluator_exclude_can_remove_closure_member() {
        // web... − utils = {web, auth, ui-button}  (utils is dropped)
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![
            FilterExpr::WithDeps(Box::new(FilterExpr::ExactName("web".into()))),
            FilterExpr::Exclude(Box::new(FilterExpr::ExactName("utils".into()))),
        ];

        let result = engine.evaluate(&exprs).unwrap();
        let set: std::collections::HashSet<_> = result.iter().copied().collect();
        assert!(set.contains(&idx(&graph, "web")));
        assert!(set.contains(&idx(&graph, "auth")));
        assert!(set.contains(&idx(&graph, "ui-button")));
        assert!(!set.contains(&idx(&graph, "utils")));
        assert_eq!(set.len(), 3);
    }

    // ── Edge cases ─────────────────────────────────────────────────────────

    #[test]
    fn evaluator_no_filters_errors() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);

        match engine.evaluate(&[]) {
            Err(FilterError::NoFilters) => {}
            other => panic!("expected NoFilters, got {other:?}"),
        }
    }

    #[test]
    fn evaluator_exclusion_only_filter_list_errors() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::Exclude(Box::new(FilterExpr::ExactName(
            "auth".into(),
        )))];

        match engine.evaluate(&exprs) {
            Err(FilterError::ExclusionOnly) => {}
            other => panic!("expected ExclusionOnly, got {other:?}"),
        }
    }

    #[test]
    fn evaluator_empty_positive_filter_returns_empty_ok() {
        // A non-matching positive filter is NOT an error; it's just an empty
        // result set. Per D3, only --fail-if-no-match escalates this.
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::ExactName("nonexistent".into())];

        let result = engine.evaluate(&exprs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn evaluator_contradictory_filters_yield_empty_ok() {
        // {auth} − auth = {} but is NOT an error.
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![
            FilterExpr::ExactName("auth".into()),
            FilterExpr::Exclude(Box::new(FilterExpr::ExactName("auth".into()))),
        ];

        let result = engine.evaluate(&exprs).unwrap();
        assert!(result.is_empty());
    }

    // ── Topological ordering and determinism ───────────────────────────────

    #[test]
    fn evaluator_returns_topologically_sorted_output() {
        // utils → auth → web. Returned order must put dependencies first.
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::WithDeps(Box::new(FilterExpr::ExactName(
            "web".into(),
        )))];

        let result = engine.evaluate(&exprs).unwrap();
        let pos = |name| {
            result
                .iter()
                .position(|&i| i == idx(&graph, name))
                .unwrap_or_else(|| panic!("{name} missing from result"))
        };
        assert!(pos("utils") < pos("auth"), "utils before auth");
        assert!(pos("auth") < pos("web"), "auth before web");
        assert!(pos("ui-button") < pos("web"), "ui-button before web");
    }

    #[test]
    fn evaluator_output_is_deterministic_across_runs() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![
            FilterExpr::WithDeps(Box::new(FilterExpr::ExactName("web".into()))),
            FilterExpr::ExactName("admin".into()),
        ];

        let first = engine.evaluate(&exprs).unwrap();
        for _ in 0..100 {
            let again = engine.evaluate(&exprs).unwrap();
            assert_eq!(again, first, "evaluator must be deterministic");
        }
    }

    // ── Helpers (split_glob_pattern, lexical_normalize) ────────────────────

    #[test]
    fn split_glob_pattern_separates_literal_and_glob() {
        assert_eq!(
            split_glob_pattern("./packages/**"),
            ("./packages".to_string(), "**".to_string())
        );
        assert_eq!(
            split_glob_pattern("./apps/*"),
            ("./apps".to_string(), "*".to_string())
        );
    }

    #[test]
    fn split_glob_pattern_handles_no_glob() {
        assert_eq!(
            split_glob_pattern("./packages/foo"),
            ("./packages/foo".to_string(), String::new())
        );
    }

    #[test]
    fn lexical_normalize_resolves_parent_dirs() {
        assert_eq!(
            lexical_normalize(Path::new("/workspace/foo/../bar")),
            PathBuf::from("/workspace/bar")
        );
    }

    #[test]
    fn lexical_normalize_resolves_current_dir() {
        assert_eq!(
            lexical_normalize(Path::new("/workspace/./foo")),
            PathBuf::from("/workspace/foo")
        );
    }

    // ── M5: Explain API tests ──────────────────────────────────────────────

    #[test]
    fn explain_atom_produces_direct_match() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::ExactName("auth".into())];

        let explain = engine.explain(&exprs).unwrap();
        assert_eq!(explain.selected, vec![idx(&graph, "auth")]);
        assert_eq!(explain.traces.len(), 1);
        match &explain.traces[0].reason {
            TraceReason::DirectMatch { filter, kind } => {
                assert_eq!(filter, "auth");
                assert_eq!(*kind, MatchKind::ExactName);
            }
            other => panic!("expected DirectMatch, got {other:?}"),
        }
        assert!(explain.notes.is_empty());
    }

    #[test]
    fn explain_glob_uses_glob_match_kind() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::GlobName("ui-*".into())];

        let explain = engine.explain(&exprs).unwrap();
        assert_eq!(explain.traces.len(), 2);
        for trace in &explain.traces {
            match &trace.reason {
                TraceReason::DirectMatch { kind, .. } => {
                    assert_eq!(*kind, MatchKind::GlobName);
                }
                other => panic!("expected GlobName DirectMatch, got {other:?}"),
            }
        }
    }

    #[test]
    fn explain_with_deps_distinguishes_seed_from_expansion() {
        // web... = {web (seed), auth, utils, ui-button (deps)}
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::WithDeps(Box::new(FilterExpr::ExactName(
            "web".into(),
        )))];

        let explain = engine.explain(&exprs).unwrap();

        let trace_for = |name: &str| -> &SelectionTrace {
            explain
                .traces
                .iter()
                .find(|t| t.package == idx(&graph, name))
                .unwrap_or_else(|| panic!("no trace for {name}"))
        };

        // The seed (web) gets DirectMatch
        match &trace_for("web").reason {
            TraceReason::DirectMatch { kind, .. } => {
                assert_eq!(*kind, MatchKind::ExactName);
            }
            other => panic!("expected DirectMatch for seed, got {other:?}"),
        }

        // Closure expansions get ViaDependency
        match &trace_for("auth").reason {
            TraceReason::ViaDependency { of, filter } => {
                assert_eq!(*of, Some(idx(&graph, "web")));
                assert_eq!(filter, "web...");
            }
            other => panic!("expected ViaDependency for auth, got {other:?}"),
        }
    }

    #[test]
    fn explain_with_dependents_marks_via_dependent() {
        // ...utils — utils is the seed; auth, web, admin are dependents
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::WithDependents(Box::new(FilterExpr::ExactName(
            "utils".into(),
        )))];

        let explain = engine.explain(&exprs).unwrap();
        let trace_for = |name: &str| -> Option<&TraceReason> {
            explain
                .traces
                .iter()
                .find(|t| t.package == idx(&graph, name))
                .map(|t| &t.reason)
        };

        assert!(matches!(
            trace_for("utils").unwrap(),
            TraceReason::DirectMatch { .. }
        ));
        match trace_for("auth").unwrap() {
            TraceReason::ViaDependent { of, .. } => {
                assert_eq!(*of, Some(idx(&graph, "utils")));
            }
            other => panic!("expected ViaDependent, got {other:?}"),
        }
    }

    #[test]
    fn explain_drops_traces_for_excluded_packages() {
        // ui-* − ui-card → only ui-button selected, only one trace
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![
            FilterExpr::GlobName("ui-*".into()),
            FilterExpr::Exclude(Box::new(FilterExpr::ExactName("ui-card".into()))),
        ];

        let explain = engine.explain(&exprs).unwrap();
        assert_eq!(explain.selected, vec![idx(&graph, "ui-button")]);
        assert_eq!(explain.traces.len(), 1);
        assert_eq!(explain.traces[0].package, idx(&graph, "ui-button"));
    }

    #[test]
    fn explain_empty_result_includes_diagnostic_note() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::ExactName("nonexistent".into())];

        let explain = engine.explain(&exprs).unwrap();
        assert!(explain.selected.is_empty());
        assert!(explain.traces.is_empty());
        assert!(!explain.notes.is_empty());
        assert!(explain.notes[0].contains("no matches"));
    }

    #[test]
    fn explain_no_filters_errors() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        match engine.explain(&[]) {
            Err(FilterError::NoFilters) => {}
            other => panic!("expected NoFilters, got {other:?}"),
        }
    }

    #[test]
    fn explain_exclusion_only_errors() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::Exclude(Box::new(FilterExpr::ExactName(
            "auth".into(),
        )))];
        match engine.explain(&exprs) {
            Err(FilterError::ExclusionOnly) => {}
            other => panic!("expected ExclusionOnly, got {other:?}"),
        }
    }

    #[test]
    fn explain_output_is_deterministic() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);
        let exprs = vec![FilterExpr::WithDeps(Box::new(FilterExpr::ExactName(
            "web".into(),
        )))];

        let first = engine.explain(&exprs).unwrap();
        for _ in 0..50 {
            let again = engine.explain(&exprs).unwrap();
            assert_eq!(again.selected, first.selected);
            assert_eq!(again.traces.len(), first.traces.len());
        }
    }

    #[test]
    fn format_expr_round_trips_simple_atoms() {
        assert_eq!(format_expr(&FilterExpr::ExactName("foo".into())), "foo");
        assert_eq!(format_expr(&FilterExpr::GlobName("@ui/*".into())), "@ui/*");
        assert_eq!(format_expr(&FilterExpr::GitRef("main".into())), "[main]");
        assert_eq!(
            format_expr(&FilterExpr::PathExact("./apps/web".into())),
            "{./apps/web}"
        );
    }

    #[test]
    fn format_expr_renders_closures() {
        let expr = FilterExpr::WithDeps(Box::new(FilterExpr::ExactName("foo".into())));
        assert_eq!(format_expr(&expr), "foo...");
        let expr = FilterExpr::DependentsOnly(Box::new(FilterExpr::GitRef("main".into())));
        assert_eq!(format_expr(&expr), "...^[main]");
    }

    // ── M6: Security tests ─────────────────────────────────────────────────
    //
    // Lock down the security boundary. The evaluator must reject path
    // escapes, glob escapes, and pass git-ref injection straight through to
    // the existing `find_affected_direct_only` plumbing (which has its own
    // injection-rejection tests under `affected::tests`).

    #[test]
    fn security_path_escape_via_parent_dir_is_rejected() {
        // Build a fixture inside a temp dir and try to escape to /etc.
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().to_path_buf();
        std::fs::create_dir_all(workspace_root.join("packages/foo")).unwrap();

        let ws = Workspace {
            root: workspace_root.clone(),
            root_package: PackageJson::default(),
            members: vec![member("foo", &[])],
        };
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &workspace_root);

        let expr = FilterExpr::PathExact("../../../etc".into());
        match engine.evaluate(&[expr]) {
            Err(FilterError::PathEscape(_)) => {}
            other => panic!("expected PathEscape, got {other:?}"),
        }
    }

    #[test]
    fn security_path_escape_via_absolute_path_outside_workspace_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().to_path_buf();

        let ws = Workspace {
            root: workspace_root.clone(),
            root_package: PackageJson::default(),
            members: vec![member("foo", &[])],
        };
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &workspace_root);

        let expr = FilterExpr::PathExact("/etc/passwd".into());
        match engine.evaluate(&[expr]) {
            Err(FilterError::PathEscape(_)) => {}
            other => panic!("expected PathEscape, got {other:?}"),
        }
    }

    #[test]
    fn security_path_glob_with_escape_in_literal_prefix_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().to_path_buf();

        let ws = Workspace {
            root: workspace_root.clone(),
            root_package: PackageJson::default(),
            members: vec![member("foo", &[])],
        };
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &workspace_root);

        let expr = FilterExpr::PathGlob("../outside/*".into());
        match engine.evaluate(&[expr]) {
            Err(FilterError::PathEscape(_)) => {}
            other => panic!("expected PathEscape from path glob, got {other:?}"),
        }
    }

    #[test]
    fn security_invalid_glob_pattern_is_rejected() {
        let (_ws, graph, root) = make_engine();
        let engine = FilterEngine::new(&graph, &root);

        // Unmatched bracket — globset rejects
        let expr = FilterExpr::GlobName("foo[".into());
        match engine.evaluate(&[expr]) {
            Err(FilterError::InvalidGlob { .. }) => {}
            other => panic!("expected InvalidGlob, got {other:?}"),
        }
    }

    #[test]
    fn security_git_ref_injection_is_rejected_by_underlying_plumbing() {
        // The git ref atom delegates to `find_affected_direct_only`, which
        // already has injection protection. This test verifies that errors
        // from the underlying plumbing surface as `FilterError::GitError`.
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().to_path_buf();

        let ws = Workspace {
            root: workspace_root.clone(),
            root_package: PackageJson::default(),
            members: vec![member("foo", &[])],
        };
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &workspace_root);

        // Empty ref is rejected by the underlying plumbing.
        let expr = FilterExpr::GitRef(String::new());
        match engine.evaluate(&[expr]) {
            Err(FilterError::GitError(_)) => {}
            other => panic!("expected GitError for empty ref, got {other:?}"),
        }

        // Flag-like ref is rejected by the underlying plumbing.
        let expr = FilterExpr::GitRef("--option=foo".into());
        match engine.evaluate(&[expr]) {
            Err(FilterError::GitError(_)) => {}
            other => panic!("expected GitError for flag-like ref, got {other:?}"),
        }
    }

    #[test]
    fn security_git_ref_with_shell_metacharacters_is_treated_as_literal() {
        // Backticks, semicolons, $() — all should be passed to git as a
        // literal ref name, NOT executed. The underlying `Command::new("git")`
        // call uses an explicit args array, so shell substitution is impossible.
        // We just verify the call doesn't panic and produces a Result.
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().to_path_buf();

        let ws = Workspace {
            root: workspace_root.clone(),
            root_package: PackageJson::default(),
            members: vec![member("foo", &[])],
        };
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &workspace_root);

        // Should produce a Result (likely Err because the ref doesn't exist
        // and the dir isn't a git repo) — but importantly, no panic, no shell
        // execution. The exact error type is not asserted because behavior
        // depends on whether git is installed.
        for evil in &["`rm -rf /`", "$(rm -rf /)", "main; echo pwned"] {
            let expr = FilterExpr::GitRef((*evil).to_string());
            let _ = engine.evaluate(&[expr]); // must not panic
        }
    }

    // ── M8: Perf assertion benchmarks ──────────────────────────────────────
    //
    // These are NOT criterion benchmarks — they're #[test]-mode perf gates
    // intended to catch order-of-magnitude regressions in the filter engine.
    // Budgets are intentionally generous (5-10x the design doc release-mode
    // numbers) so they pass in debug mode where every test runs.
    //
    // For tighter benchmarking, drive the bench/run.sh harness in Phase 0.2.
    //
    // The fixture is a 200-member synthetic workspace with a 5-deep dependency
    // chain in the middle, so closure operators have non-trivial work.

    fn build_perf_fixture(size: usize) -> Workspace {
        let mut members: Vec<WorkspaceMember> = Vec::with_capacity(size);
        // First 5 form a dependency chain: pkg-0 ← pkg-1 ← pkg-2 ← pkg-3 ← pkg-4
        for i in 0..size {
            let deps: Vec<&str> = if i > 0 && i < 5 {
                // pkg-1..pkg-4 each depend on the previous
                vec![]
            } else {
                vec![]
            };
            // Use a Vec of owned String to make `&str` borrows happy
            let dep_names: Vec<String> = if i > 0 && i < 5 {
                vec![format!("pkg-{}", i - 1)]
            } else {
                Vec::new()
            };
            let dep_refs: Vec<&str> = dep_names.iter().map(String::as_str).collect();
            let _ = deps;
            members.push(member(&format!("pkg-{i}"), &dep_refs));
        }
        Workspace {
            root: PathBuf::from("/workspace"),
            root_package: PackageJson::default(),
            members,
        }
    }

    /// Run a closure repeatedly and report nanoseconds per iteration
    /// — best-of-N rounds so a single scheduler stall on a shared CI
    /// runner doesn't sink the measurement.
    ///
    /// A single round of the earlier `total_elapsed / iters` shape
    /// was very sensitive to OS scheduling on GitHub Actions: one
    /// 500ms stall across a 500-iter loop adds 1ms to every per-op
    /// sample, which is 2× the 500µs debug budget — the glob
    /// eval test flaked exactly this way on 2026-04-23 (CI run
    /// 24830202402, Linux `ubuntu-latest`). Best-of-N captures
    /// "when the scheduler cooperated, how fast can this code
    /// run?" — the question a ns/op budget is actually asking, and
    /// the one a regression in LPM's own code would answer with a
    /// shift in ALL rounds (not just one).
    fn time_per_op(iters_per_round: u32, mut op: impl FnMut()) -> u128 {
        const ROUNDS: u32 = 5;
        let mut best = u128::MAX;
        for _ in 0..ROUNDS {
            let start = std::time::Instant::now();
            for _ in 0..iters_per_round {
                op();
            }
            let this = start.elapsed().as_nanos() / iters_per_round as u128;
            if this < best {
                best = this;
            }
        }
        best
    }

    #[test]
    fn perf_parse_under_50us_per_call() {
        // Design doc target: 10µs release. Debug budget: 50µs.
        let ns = time_per_op(2_000, || {
            let _ = crate::filter::parse("./packages/**...").unwrap();
        });
        assert!(
            ns < 50_000,
            "parse perf regressed: {ns}ns/op (budget 50µs/op debug, best-of-5)"
        );
    }

    #[test]
    fn perf_eval_exact_name_under_50us_per_call() {
        // Design doc target: 5µs release. Debug budget: 50µs.
        let ws = build_perf_fixture(200);
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &ws.root);
        let exprs = vec![FilterExpr::ExactName("pkg-100".into())];

        let ns = time_per_op(2_000, || {
            let _ = engine.evaluate(&exprs).unwrap();
        });
        assert!(
            ns < 50_000,
            "exact-name eval regressed on 200-member workspace: {ns}ns/op \
             (budget 50µs/op debug, best-of-5)"
        );
    }

    #[test]
    fn perf_eval_glob_200_members_under_500us_per_call() {
        // Design doc target: 100µs release. Debug budget: 500µs.
        let ws = build_perf_fixture(200);
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &ws.root);
        let exprs = vec![FilterExpr::GlobName("pkg-*".into())];

        let ns = time_per_op(500, || {
            let _ = engine.evaluate(&exprs).unwrap();
        });
        assert!(
            ns < 500_000,
            "glob eval regressed on 200-member workspace: {ns}ns/op \
             (budget 500µs/op debug, best-of-5)"
        );
    }

    #[test]
    fn perf_eval_closure_with_deps_under_500us_per_call() {
        // Design doc target: 200µs release. Debug budget: 500µs.
        let ws = build_perf_fixture(200);
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &ws.root);
        // pkg-4... = {pkg-4, pkg-3, pkg-2, pkg-1, pkg-0} (5-deep chain in fixture)
        let exprs = vec![FilterExpr::WithDeps(Box::new(FilterExpr::ExactName(
            "pkg-4".into(),
        )))];

        let ns = time_per_op(500, || {
            let _ = engine.evaluate(&exprs).unwrap();
        });
        assert!(
            ns < 500_000,
            "closure-with-deps eval regressed on 200-member workspace: {ns}ns/op (budget 500µs/op debug)"
        );
    }

    #[test]
    fn perf_eval_ten_compound_filters_under_5ms_per_call() {
        // Design doc target: 1ms release. Debug budget: 5ms.
        let ws = build_perf_fixture(200);
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &ws.root);
        let exprs = vec![
            FilterExpr::ExactName("pkg-1".into()),
            FilterExpr::ExactName("pkg-2".into()),
            FilterExpr::ExactName("pkg-3".into()),
            FilterExpr::GlobName("pkg-1*".into()),
            FilterExpr::GlobName("pkg-9*".into()),
            FilterExpr::WithDeps(Box::new(FilterExpr::ExactName("pkg-4".into()))),
            FilterExpr::WithDependents(Box::new(FilterExpr::ExactName("pkg-0".into()))),
            FilterExpr::ExactName("pkg-50".into()),
            FilterExpr::ExactName("pkg-150".into()),
            FilterExpr::Exclude(Box::new(FilterExpr::ExactName("pkg-2".into()))),
        ];

        let ns = time_per_op(200, || {
            let _ = engine.evaluate(&exprs).unwrap();
        });
        assert!(
            ns < 5_000_000,
            "compound 10-filter eval regressed: {ns}ns/op (budget 5ms/op debug)"
        );
    }

    #[test]
    fn security_path_exact_lexical_normalization_handles_dot_dot_within_root() {
        // ./packages/foo/../bar should resolve to ./packages/bar — that's
        // legal because it stays inside the workspace. Only escapes outside
        // the workspace root are rejected.
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().to_path_buf();
        std::fs::create_dir_all(workspace_root.join("packages/bar")).unwrap();

        let ws = Workspace {
            root: workspace_root.clone(),
            root_package: PackageJson {
                name: Some("root".into()),
                ..Default::default()
            },
            members: vec![WorkspaceMember {
                path: workspace_root.join("packages/bar"),
                package: PackageJson {
                    name: Some("bar".into()),
                    ..Default::default()
                },
            }],
        };
        let graph = WorkspaceGraph::from_workspace(&ws);
        let engine = FilterEngine::new(&graph, &workspace_root);

        let expr = FilterExpr::PathExact("./packages/foo/../bar".into());
        let result = engine.evaluate(&[expr]).unwrap();
        // bar should be selected — the .. stayed inside workspace_root
        assert_eq!(result, vec![idx(&graph, "bar")]);
    }
}
