//! Filter expression parser.
//!
//! Hand-written recursive descent. No external parser generator. The grammar
//! is small and the error messages are better when written by hand.
//!
//! ## Grammar (informal EBNF, design doc §6)
//!
//! ```text
//! filter      := exclusion | directional
//! exclusion   := "!" directional
//! directional := "..." inner_dir          (* reverse closure *)
//!              | inner_fwd "..."          (* forward closure *)
//!              | atom
//! inner_dir   := "^" atom                  (* ...^foo = dependents-only *)
//!              | atom                       (* ...foo  = with-dependents *)
//! inner_fwd   := atom "^"                  (* foo^... = deps-only *)
//!              | atom                       (* foo...  = with-deps *)
//! atom        := git_ref | path_exact | path_glob | name_glob | name
//! git_ref     := "[" <ref characters> "]"
//! path_exact  := "{" path "}"
//! path_glob   := "./" <glob chars> | "../" <glob chars>
//! name_glob   := <package name with * or ?>
//! name        := <package name>
//! ```
//!
//! Whitespace is not allowed inside a single filter — `--filter "foo ..."`
//! parses as the literal string `foo ...` and fails. Multi-filter is
//! handled by passing multiple `--filter` flags, not by space-separating.

use super::FilterExpr;

/// Parser error variants. Each error includes enough context for the
/// `--explain` flow to point at the offending position when rendering.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("empty filter")]
    Empty,

    #[error("unclosed git ref bracket: {0:?}")]
    UnclosedGitRef(String),

    #[error("unclosed path literal: {0:?}")]
    UnclosedPath(String),

    #[error("double negation not allowed: {0:?}")]
    DoubleNegation(String),

    #[error("exclusion must be top-level (no nesting inside closures): {0:?}")]
    NestedExclusion(String),

    #[error("closure operators cannot be combined in a single filter: {0:?}")]
    AmbiguousClosure(String),

    #[error("unexpected character {ch:?} at position {pos} in filter {input:?}")]
    UnexpectedChar {
        ch: char,
        pos: usize,
        input: String,
    },

    #[error("invalid glob pattern in filter: {0:?}")]
    InvalidGlob(String),

    #[error("path filter must start with `./` or `../`: {0:?}")]
    InvalidPathFilter(String),
}

/// Parse a single filter expression string into a `FilterExpr`.
///
/// Multi-filter (`--filter A --filter B`) is handled at the call site by
/// invoking `parse` once per CLI argument and combining the results in
/// `FilterEngine::evaluate`.
pub fn parse(input: &str) -> Result<FilterExpr, ParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }
    // Reject internal whitespace. A single filter is one token; multi-filter
    // is multiple --filter flags. `--filter "foo bar"` is a user error.
    if let Some((pos, ch)) = trimmed
        .char_indices()
        .find(|(_, c)| c.is_whitespace())
    {
        return Err(ParseError::UnexpectedChar {
            ch,
            pos,
            input: input.to_string(),
        });
    }
    parse_filter(trimmed, input)
}

/// Top-level parser entry: handles exclusion prefix, then dispatches to
/// `parse_directional`.
fn parse_filter(s: &str, original_input: &str) -> Result<FilterExpr, ParseError> {
    if let Some(rest) = s.strip_prefix('!') {
        // Top-level exclusion. Reject double negation and nested exclusion.
        if rest.starts_with('!') {
            return Err(ParseError::DoubleNegation(original_input.to_string()));
        }
        if rest.is_empty() {
            return Err(ParseError::Empty);
        }
        let inner = parse_directional(rest, original_input)?;
        if inner.is_exclude() {
            return Err(ParseError::NestedExclusion(original_input.to_string()));
        }
        return Ok(FilterExpr::Exclude(Box::new(inner)));
    }
    parse_directional(s, original_input)
}

/// Parse a directional expression: an atom optionally wrapped in a closure
/// operator (`...` prefix or suffix). Rejects ambiguous closure combinations.
fn parse_directional(s: &str, original_input: &str) -> Result<FilterExpr, ParseError> {
    let starts_with_dots = s.starts_with("...");
    let ends_with_dots = s.ends_with("...");

    if starts_with_dots && ends_with_dots && s.len() > 3 {
        // Both leading and trailing `...` — ambiguous.
        return Err(ParseError::AmbiguousClosure(original_input.to_string()));
    }

    if starts_with_dots {
        // Reverse closure: `...foo` or `...^foo`.
        let after = &s[3..];
        if after.is_empty() {
            return Err(ParseError::UnexpectedChar {
                ch: '.',
                pos: 0,
                input: original_input.to_string(),
            });
        }
        let (inner_str, dependents_only) = if let Some(stripped) = after.strip_prefix('^') {
            (stripped, true)
        } else {
            (after, false)
        };
        if inner_str.is_empty() {
            return Err(ParseError::Empty);
        }
        let inner = parse_atom(inner_str, original_input)?;
        return Ok(if dependents_only {
            FilterExpr::DependentsOnly(Box::new(inner))
        } else {
            FilterExpr::WithDependents(Box::new(inner))
        });
    }

    if ends_with_dots {
        // Forward closure: `foo...` or `foo^...`.
        let before = &s[..s.len() - 3];
        if before.is_empty() {
            return Err(ParseError::UnexpectedChar {
                ch: '.',
                pos: 0,
                input: original_input.to_string(),
            });
        }
        let (atom_str, deps_only) = if let Some(stripped) = before.strip_suffix('^') {
            (stripped, true)
        } else {
            (before, false)
        };
        if atom_str.is_empty() {
            return Err(ParseError::Empty);
        }
        let inner = parse_atom(atom_str, original_input)?;
        return Ok(if deps_only {
            FilterExpr::DepsOnly(Box::new(inner))
        } else {
            FilterExpr::WithDeps(Box::new(inner))
        });
    }

    // No closure operator — just a bare atom.
    parse_atom(s, original_input)
}

/// Parse an atom: git ref, path exact, path glob, name glob, or bare name.
fn parse_atom(s: &str, original_input: &str) -> Result<FilterExpr, ParseError> {
    if s.is_empty() {
        return Err(ParseError::Empty);
    }

    // Git ref: `[<ref>]`
    if let Some(after_open) = s.strip_prefix('[') {
        let inner = after_open
            .strip_suffix(']')
            .ok_or_else(|| ParseError::UnclosedGitRef(original_input.to_string()))?;
        if inner.is_empty() {
            return Err(ParseError::Empty);
        }
        return Ok(FilterExpr::GitRef(inner.to_string()));
    }

    // Path exact: `{<path>}`
    if let Some(after_open) = s.strip_prefix('{') {
        let inner = after_open
            .strip_suffix('}')
            .ok_or_else(|| ParseError::UnclosedPath(original_input.to_string()))?;
        if inner.is_empty() {
            return Err(ParseError::Empty);
        }
        return Ok(FilterExpr::PathExact(inner.to_string()));
    }

    // Path glob: starts with `./` or `../`
    if s.starts_with("./") || s.starts_with("../") {
        // Reject embedded `[` and `{` which would be ambiguous with other atoms
        if s.contains('[') || s.contains('{') {
            return Err(ParseError::InvalidPathFilter(original_input.to_string()));
        }
        return Ok(FilterExpr::PathGlob(s.to_string()));
    }

    // Reject characters that are not legal anywhere in a bare-name atom.
    // Catches `foo!bar`, `foo[bar`, `foo{bar`, bare `]` / `}`, etc.
    for (pos, ch) in s.chars().enumerate() {
        match ch {
            '!' | '[' | ']' | '{' | '}' => {
                return Err(ParseError::UnexpectedChar {
                    ch,
                    pos,
                    input: original_input.to_string(),
                });
            }
            _ => {}
        }
    }

    // Glob name: contains `*` or `?`
    if s.contains('*') || s.contains('?') {
        return Ok(FilterExpr::GlobName(s.to_string()));
    }

    // Bare name (exact match per D2)
    Ok(FilterExpr::ExactName(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Bare name atoms ───────────────────────────────────────────────────

    #[test]
    fn parses_bare_unscoped_name() {
        assert_eq!(parse("foo").unwrap(), FilterExpr::ExactName("foo".into()));
    }

    #[test]
    fn parses_scoped_name() {
        assert_eq!(
            parse("@scope/pkg").unwrap(),
            FilterExpr::ExactName("@scope/pkg".into())
        );
    }

    #[test]
    fn parses_name_with_dots_and_hyphens() {
        assert_eq!(
            parse("@lpm.dev/acme.foo-bar").unwrap(),
            FilterExpr::ExactName("@lpm.dev/acme.foo-bar".into())
        );
    }

    #[test]
    fn trims_leading_and_trailing_whitespace() {
        assert_eq!(parse("  foo  ").unwrap(), FilterExpr::ExactName("foo".into()));
    }

    // ── Glob atoms ────────────────────────────────────────────────────────

    #[test]
    fn parses_simple_glob() {
        assert_eq!(parse("foo-*").unwrap(), FilterExpr::GlobName("foo-*".into()));
    }

    #[test]
    fn parses_scope_glob() {
        assert_eq!(
            parse("@babel/*").unwrap(),
            FilterExpr::GlobName("@babel/*".into())
        );
    }

    #[test]
    fn parses_question_mark_glob() {
        assert_eq!(
            parse("pkg?").unwrap(),
            FilterExpr::GlobName("pkg?".into())
        );
    }

    // ── Path atoms ────────────────────────────────────────────────────────

    #[test]
    fn parses_path_glob_relative() {
        assert_eq!(
            parse("./packages/**").unwrap(),
            FilterExpr::PathGlob("./packages/**".into())
        );
    }

    #[test]
    fn parses_path_glob_parent() {
        assert_eq!(
            parse("../sibling/*").unwrap(),
            FilterExpr::PathGlob("../sibling/*".into())
        );
    }

    #[test]
    fn parses_path_exact_braces() {
        assert_eq!(
            parse("{./apps/web}").unwrap(),
            FilterExpr::PathExact("./apps/web".into())
        );
    }

    #[test]
    fn parses_path_exact_without_dot_prefix() {
        assert_eq!(
            parse("{packages/foo}").unwrap(),
            FilterExpr::PathExact("packages/foo".into())
        );
    }

    // ── Git ref atoms ─────────────────────────────────────────────────────

    #[test]
    fn parses_git_ref_simple() {
        assert_eq!(
            parse("[main]").unwrap(),
            FilterExpr::GitRef("main".into())
        );
    }

    #[test]
    fn parses_git_ref_origin() {
        assert_eq!(
            parse("[origin/main]").unwrap(),
            FilterExpr::GitRef("origin/main".into())
        );
    }

    #[test]
    fn parses_git_ref_with_tilde() {
        assert_eq!(
            parse("[HEAD~5]").unwrap(),
            FilterExpr::GitRef("HEAD~5".into())
        );
    }

    #[test]
    fn parses_git_ref_with_tag() {
        assert_eq!(
            parse("[v1.2.3]").unwrap(),
            FilterExpr::GitRef("v1.2.3".into())
        );
    }

    // ── Forward closure operators ─────────────────────────────────────────

    #[test]
    fn parses_with_deps_closure() {
        assert_eq!(
            parse("foo...").unwrap(),
            FilterExpr::WithDeps(Box::new(FilterExpr::ExactName("foo".into())))
        );
    }

    #[test]
    fn parses_deps_only_closure() {
        assert_eq!(
            parse("foo^...").unwrap(),
            FilterExpr::DepsOnly(Box::new(FilterExpr::ExactName("foo".into())))
        );
    }

    #[test]
    fn parses_with_deps_over_glob() {
        assert_eq!(
            parse("@ui/*...").unwrap(),
            FilterExpr::WithDeps(Box::new(FilterExpr::GlobName("@ui/*".into())))
        );
    }

    #[test]
    fn parses_with_deps_over_path() {
        assert_eq!(
            parse("./apps/*...").unwrap(),
            FilterExpr::WithDeps(Box::new(FilterExpr::PathGlob("./apps/*".into())))
        );
    }

    #[test]
    fn parses_with_deps_over_git_ref() {
        assert_eq!(
            parse("[main]...").unwrap(),
            FilterExpr::WithDeps(Box::new(FilterExpr::GitRef("main".into())))
        );
    }

    // ── Reverse closure operators ─────────────────────────────────────────

    #[test]
    fn parses_with_dependents_closure() {
        assert_eq!(
            parse("...foo").unwrap(),
            FilterExpr::WithDependents(Box::new(FilterExpr::ExactName("foo".into())))
        );
    }

    #[test]
    fn parses_dependents_only_closure() {
        assert_eq!(
            parse("...^foo").unwrap(),
            FilterExpr::DependentsOnly(Box::new(FilterExpr::ExactName("foo".into())))
        );
    }

    #[test]
    fn parses_with_dependents_over_git_ref() {
        // The canonical CI use case: `...[main]` = "everything affected since main"
        assert_eq!(
            parse("...[origin/main]").unwrap(),
            FilterExpr::WithDependents(Box::new(FilterExpr::GitRef("origin/main".into())))
        );
    }

    #[test]
    fn parses_dependents_only_over_path() {
        assert_eq!(
            parse("...^./apps/web").unwrap(),
            FilterExpr::DependentsOnly(Box::new(FilterExpr::PathGlob("./apps/web".into())))
        );
    }

    // ── Top-level exclusion ───────────────────────────────────────────────

    #[test]
    fn parses_exclusion_of_bare_name() {
        assert_eq!(
            parse("!foo").unwrap(),
            FilterExpr::Exclude(Box::new(FilterExpr::ExactName("foo".into())))
        );
    }

    #[test]
    fn parses_exclusion_of_path_glob() {
        assert_eq!(
            parse("!./apps/*").unwrap(),
            FilterExpr::Exclude(Box::new(FilterExpr::PathGlob("./apps/*".into())))
        );
    }

    #[test]
    fn parses_exclusion_of_git_ref() {
        assert_eq!(
            parse("![main]").unwrap(),
            FilterExpr::Exclude(Box::new(FilterExpr::GitRef("main".into())))
        );
    }

    #[test]
    fn parses_exclusion_of_closure() {
        // `!foo...` = exclude (foo + its deps)
        assert_eq!(
            parse("!foo...").unwrap(),
            FilterExpr::Exclude(Box::new(FilterExpr::WithDeps(Box::new(
                FilterExpr::ExactName("foo".into())
            ))))
        );
    }

    // ── Error cases ───────────────────────────────────────────────────────

    #[test]
    fn rejects_empty_input() {
        assert_eq!(parse("").unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn rejects_whitespace_only_input() {
        assert_eq!(parse("   ").unwrap_err(), ParseError::Empty);
    }

    #[test]
    fn rejects_internal_whitespace() {
        match parse("foo bar") {
            Err(ParseError::UnexpectedChar { ch, pos, .. }) => {
                assert_eq!(ch, ' ');
                assert_eq!(pos, 3);
            }
            other => panic!("expected UnexpectedChar for space, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unclosed_git_ref() {
        match parse("[main") {
            Err(ParseError::UnclosedGitRef(_)) => {}
            other => panic!("expected UnclosedGitRef, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unclosed_path_literal() {
        match parse("{./apps/web") {
            Err(ParseError::UnclosedPath(_)) => {}
            other => panic!("expected UnclosedPath, got {other:?}"),
        }
    }

    #[test]
    fn rejects_double_negation() {
        match parse("!!foo") {
            Err(ParseError::DoubleNegation(_)) => {}
            other => panic!("expected DoubleNegation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_ambiguous_double_closure() {
        match parse("...foo...") {
            Err(ParseError::AmbiguousClosure(_)) => {}
            other => panic!("expected AmbiguousClosure, got {other:?}"),
        }
    }

    #[test]
    fn rejects_mid_string_exclamation() {
        match parse("foo!bar") {
            Err(ParseError::UnexpectedChar { ch: '!', .. }) => {}
            other => panic!("expected UnexpectedChar for !, got {other:?}"),
        }
    }

    #[test]
    fn rejects_mid_string_open_bracket() {
        match parse("foo[bar") {
            Err(ParseError::UnexpectedChar { ch: '[', .. }) => {}
            other => panic!("expected UnexpectedChar for [, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bare_close_bracket() {
        match parse("foo]") {
            Err(ParseError::UnexpectedChar { ch: ']', .. }) => {}
            other => panic!("expected UnexpectedChar for ], got {other:?}"),
        }
    }

    #[test]
    fn rejects_lonely_dots() {
        match parse("...") {
            Err(_) => {}
            Ok(other) => panic!("expected error for lonely dots, got {other:?}"),
        }
    }

    #[test]
    fn rejects_dots_with_caret_only() {
        match parse("...^") {
            Err(_) => {}
            Ok(other) => panic!("expected error for empty atom after caret, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_git_ref_brackets() {
        match parse("[]") {
            Err(ParseError::Empty) => {}
            other => panic!("expected Empty for [], got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_path_braces() {
        match parse("{}") {
            Err(ParseError::Empty) => {}
            other => panic!("expected Empty for {{}}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_negation_of_nothing() {
        match parse("!") {
            Err(ParseError::Empty) => {}
            other => panic!("expected Empty for lone !, got {other:?}"),
        }
    }

    // ── Position-aware errors ─────────────────────────────────────────────

    #[test]
    fn unexpected_char_error_records_position() {
        match parse("ab!cd") {
            Err(ParseError::UnexpectedChar { ch, pos, input }) => {
                assert_eq!(ch, '!');
                assert_eq!(pos, 2);
                assert_eq!(input, "ab!cd");
            }
            other => panic!("expected UnexpectedChar with position, got {other:?}"),
        }
    }
}

