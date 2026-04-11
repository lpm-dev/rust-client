//! `lpm filter` — read-only preview of the workspace package set that a
//! `--filter` expression would select.
//!
//! Drives the same `FilterEngine` as `lpm run --filter`, so the result is
//! byte-identical to what `lpm run` would target. Used by humans to preview
//! a filter before committing to a mutating command, and by AI agents
//! through the `--json` output to plan workspace operations.
//!
//! Phase 32 Phase 1 deliverable. Future phases will expose this through the
//! MCP `lpm_filter_preview` tool sharing the same engine.

use crate::output;
use lpm_common::LpmError;
use lpm_task::filter::{FilterEngine, FilterExpr, MatchKind, TraceReason};
use lpm_task::graph::WorkspaceGraph;
use owo_colors::OwoColorize;
use std::path::Path;

/// Format the D2 substring → glob migration hint when a filter set returns
/// no matches and at least one filter looks like a bare name that would
/// have matched in the pre-Phase-32 substring matcher.
///
/// Returns `None` when no filters look like substring-style names (e.g., the
/// user passed only globs, paths, or git-refs — they're already on the new
/// model and don't need the hint).
///
/// Per design decision D2 / Phase 1 release notes follow-through.
pub(crate) fn format_no_match_hint(raw_filters: &[String]) -> Option<String> {
    let suggestions: Vec<String> = raw_filters
        .iter()
        .filter(|raw| looks_like_bare_name(raw))
        .map(|raw| {
            // Suggest both common migration paths: substring-replacement and
            // suffix-after-scope. The user picks whichever matches their intent.
            format!("    {raw:?}  →  use {0:?} (any name containing '{raw}')  or  {1:?} (suffix-after-scope)",
                format!("*{raw}*"),
                format!("*/{raw}"),
            )
        })
        .collect();

    if suggestions.is_empty() {
        return None;
    }

    Some(format!(
        "Phase 32 removed the legacy substring matcher (design decision D2).\n\
         Bare names are now strict exact matches. To recover the old behavior:\n\n\
         {}\n\n\
         See `lpm filter --help` for the full grammar reference.",
        suggestions.join("\n")
    ))
}

/// Heuristic: does this filter string look like a bare name (no special
/// characters), suggesting the user might be expecting substring matching?
///
/// Returns false for globs (`*`, `?`), paths (`./`, `../`), git refs (`[`),
/// path-exact (`{`), exclusions (`!`), and closures (`...`).
fn looks_like_bare_name(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    !trimmed.contains('*')
        && !trimmed.contains('?')
        && !trimmed.starts_with("./")
        && !trimmed.starts_with("../")
        && !trimmed.starts_with('[')
        && !trimmed.starts_with('{')
        && !trimmed.starts_with('!')
        && !trimmed.contains("...")
}

pub async fn run(
    project_dir: &Path,
    exprs: &[String],
    explain_mode: bool,
    fail_if_no_match: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .map_err(|e| LpmError::Script(format!("workspace error: {e}")))?
        .ok_or_else(|| {
            LpmError::Script("no workspace found. `lpm filter` requires a monorepo".into())
        })?;

    let graph = WorkspaceGraph::from_workspace(&workspace);
    let engine = FilterEngine::new(&graph, &workspace.root);

    // Parse all CLI exprs through the same parser as `lpm run --filter`.
    let mut parsed: Vec<FilterExpr> = Vec::with_capacity(exprs.len());
    for raw in exprs {
        parsed.push(
            FilterEngine::parse(raw)
                .map_err(|e| LpmError::Script(format!("invalid filter {raw:?}: {e}")))?,
        );
    }

    let mut explain = engine
        .explain(&parsed)
        .map_err(|e| LpmError::Script(format!("filter error: {e}")))?;

    // Populate the input field that the engine leaves empty.
    explain.input = exprs.to_vec();

    if json_output {
        // Stable JSON shape for agents. Always includes the full trace
        // because JSON is structured output — `--explain` only affects
        // human rendering. Phase 9 (`--report-json`) will formalize the
        // schema version field.
        let traces: Vec<serde_json::Value> = explain
            .traces
            .iter()
            .map(|t| {
                let pkg_name = graph
                    .members
                    .get(t.package)
                    .map(|m| m.name.as_str())
                    .unwrap_or("?");
                serde_json::json!({
                    "package": pkg_name,
                    "package_id": t.package,
                    "reason": trace_reason_to_json(&t.reason),
                })
            })
            .collect();
        let selected_names: Vec<&str> = explain
            .selected
            .iter()
            .map(|&id| {
                graph
                    .members
                    .get(id)
                    .map(|m| m.name.as_str())
                    .unwrap_or("?")
            })
            .collect();
        let payload = serde_json::json!({
            "input": explain.input,
            "selected": selected_names,
            "selected_count": explain.selected.len(),
            "total_members": graph.len(),
            "traces": traces,
            "notes": explain.notes,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else if explain_mode {
        render_human_explain(&graph, &explain);
    } else {
        render_human_terse(&graph, &explain);
    }

    if explain.selected.is_empty() && fail_if_no_match {
        return Err(LpmError::Script(
            "no workspace packages matched the filter (--fail-if-no-match)".into(),
        ));
    }

    Ok(())
}

/// Shared empty-result rendering used by both terse and explain modes.
/// Surfaces the D2 substring → glob migration hint when applicable.
fn render_no_match(explain: &lpm_task::filter::FilterExplain) {
    output::warn("Filter set produced no matches.");
    for note in &explain.notes {
        println!("  {}", note.dimmed());
    }
    if let Some(hint) = format_no_match_hint(&explain.input) {
        println!();
        for line in hint.lines() {
            println!("  {}", line.dimmed());
        }
    }
    println!();
}

/// Default human rendering: terse name list, one per line. Suitable for
/// piping into shell tools (`lpm filter "@ui/*" | xargs ...`).
fn render_human_terse(graph: &WorkspaceGraph, explain: &lpm_task::filter::FilterExplain) {
    if explain.selected.is_empty() {
        println!();
        render_no_match(explain);
        return;
    }
    for &id in &explain.selected {
        if let Some(member) = graph.members.get(id) {
            println!("{}", member.name);
        }
    }
}

/// Verbose human rendering (`lpm filter --explain`): full per-package trace
/// with the matched filter and reason kind. Each row shows package name,
/// directory, and a "matched X (kind)" or "dependency of Y via X" annotation.
fn render_human_explain(graph: &WorkspaceGraph, explain: &lpm_task::filter::FilterExplain) {
    println!();
    if explain.selected.is_empty() {
        render_no_match(explain);
        return;
    }

    output::success(&format!(
        "Selected {} of {} workspace packages",
        explain.selected.len().to_string().bold(),
        graph.len()
    ));
    println!();

    // Build a quick package_id → trace lookup so we can render in
    // selection order with the correct trace alongside.
    let trace_for = |id: usize| -> Option<&lpm_task::filter::SelectionTrace> {
        explain.traces.iter().find(|t| t.package == id)
    };

    for &id in &explain.selected {
        let name = graph
            .members
            .get(id)
            .map(|m| m.name.as_str())
            .unwrap_or("?");
        let path = graph
            .members
            .get(id)
            .map(|m| m.path.display().to_string())
            .unwrap_or_default();

        let reason = trace_for(id).map(|t| describe_reason(graph, &t.reason));
        match reason {
            Some(r) => println!("  {}  {}  {}", name.bold(), path.dimmed(), r.dimmed()),
            None => println!("  {}  {}", name.bold(), path.dimmed()),
        }
    }
    println!();
}

fn describe_reason(graph: &WorkspaceGraph, reason: &TraceReason) -> String {
    match reason {
        TraceReason::DirectMatch { filter, kind } => {
            let kind_label = match kind {
                MatchKind::ExactName => "name",
                MatchKind::GlobName => "glob",
                MatchKind::PathGlob => "path-glob",
                MatchKind::PathExact => "path",
                MatchKind::GitRef => "git-ref",
            };
            format!("matched {filter:?} ({kind_label})")
        }
        TraceReason::ViaDependency { of, filter } => {
            let of_label = of
                .and_then(|id| graph.members.get(id).map(|m| m.name.clone()))
                .unwrap_or_else(|| "(multiple)".to_string());
            format!("dependency of {of_label} via {filter:?}")
        }
        TraceReason::ViaDependent { of, filter } => {
            let of_label = of
                .and_then(|id| graph.members.get(id).map(|m| m.name.clone()))
                .unwrap_or_else(|| "(multiple)".to_string());
            format!("dependent of {of_label} via {filter:?}")
        }
    }
}

fn trace_reason_to_json(reason: &TraceReason) -> serde_json::Value {
    match reason {
        TraceReason::DirectMatch { filter, kind } => serde_json::json!({
            "type": "direct_match",
            "filter": filter,
            "kind": match kind {
                MatchKind::ExactName => "exact_name",
                MatchKind::GlobName => "glob_name",
                MatchKind::PathGlob => "path_glob",
                MatchKind::PathExact => "path_exact",
                MatchKind::GitRef => "git_ref",
            },
        }),
        TraceReason::ViaDependency { of, filter } => serde_json::json!({
            "type": "via_dependency",
            "of_package_id": of,
            "filter": filter,
        }),
        TraceReason::ViaDependent { of, filter } => serde_json::json!({
            "type": "via_dependent",
            "of_package_id": of,
            "filter": filter,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── D2 no-match migration hint regressions ─────────────────────────────

    #[test]
    fn no_match_hint_fires_for_bare_unscoped_name() {
        let hint = format_no_match_hint(&["core".to_string()]).expect("hint should fire");
        assert!(
            hint.contains("D2"),
            "hint must reference design decision D2"
        );
        assert!(
            hint.contains("\"*core*\""),
            "hint must suggest the substring-style glob form"
        );
        assert!(
            hint.contains("\"*/core\""),
            "hint must suggest the suffix-after-scope form"
        );
    }

    #[test]
    fn no_match_hint_fires_for_bare_scoped_name() {
        // `@scope/foo` is a bare name (no glob chars) and previously would
        // have substring-matched `@scope/foo-bar`. Hint should fire.
        let hint = format_no_match_hint(&["@scope/foo".to_string()]).expect("hint should fire");
        assert!(hint.contains("\"*@scope/foo*\""));
    }

    #[test]
    fn no_match_hint_fires_for_multiple_bare_names() {
        let hint = format_no_match_hint(&["core".to_string(), "auth".to_string()])
            .expect("hint should fire");
        assert!(hint.contains("\"core\""));
        assert!(hint.contains("\"auth\""));
    }

    #[test]
    fn no_match_hint_does_not_fire_for_glob_only_filters() {
        // The user is already using globs — they're on the new model,
        // no migration hint needed.
        assert!(format_no_match_hint(&["*-core".to_string()]).is_none());
        assert!(format_no_match_hint(&["@ui/*".to_string()]).is_none());
        assert!(format_no_match_hint(&["foo*bar".to_string()]).is_none());
    }

    #[test]
    fn no_match_hint_does_not_fire_for_path_filters() {
        assert!(format_no_match_hint(&["./apps/foo".to_string()]).is_none());
        assert!(format_no_match_hint(&["{./packages/bar}".to_string()]).is_none());
        assert!(format_no_match_hint(&["../sibling".to_string()]).is_none());
    }

    #[test]
    fn no_match_hint_does_not_fire_for_git_ref_or_closure() {
        assert!(format_no_match_hint(&["[main]".to_string()]).is_none());
        assert!(format_no_match_hint(&["...foo".to_string()]).is_none());
        assert!(format_no_match_hint(&["foo...".to_string()]).is_none());
    }

    #[test]
    fn no_match_hint_does_not_fire_for_exclusion() {
        // An exclusion-only filter list is its own error class (ExclusionOnly)
        // and never reaches the no-match path. But the heuristic should
        // still skip exclusion filters mixed with positive ones.
        assert!(format_no_match_hint(&["!foo".to_string()]).is_none());
    }

    #[test]
    fn no_match_hint_skips_glob_filters_in_mixed_list_but_fires_for_bare_names() {
        // If the filter list mixes a bare name (which might be the typo) with
        // a glob (which is fine), the hint should still fire for the bare name.
        let hint = format_no_match_hint(&["core".to_string(), "@ui/*".to_string()])
            .expect("hint should fire for the bare name");
        assert!(hint.contains("\"core\""));
        // The glob filter should NOT appear in the hint suggestions
        assert!(!hint.contains("\"@ui/*\""));
    }

    #[test]
    fn no_match_hint_returns_none_for_empty_filter_list() {
        assert!(format_no_match_hint(&[]).is_none());
    }

    #[test]
    fn no_match_hint_returns_none_for_whitespace_only_filter() {
        // Defensive — whitespace-only would have been rejected by the parser
        // earlier in the pipeline, but the helper should still handle it.
        assert!(format_no_match_hint(&["   ".to_string()]).is_none());
    }

    // ── looks_like_bare_name heuristic ─────────────────────────────────────

    #[test]
    fn looks_like_bare_name_classifies_correctly() {
        // Bare names (yes)
        assert!(looks_like_bare_name("core"));
        assert!(looks_like_bare_name("@scope/foo"));
        assert!(looks_like_bare_name("foo-bar.baz"));

        // Globs (no)
        assert!(!looks_like_bare_name("*"));
        assert!(!looks_like_bare_name("foo-*"));
        assert!(!looks_like_bare_name("@ui/*"));
        assert!(!looks_like_bare_name("foo?"));

        // Paths (no)
        assert!(!looks_like_bare_name("./packages/foo"));
        assert!(!looks_like_bare_name("../sibling"));
        assert!(!looks_like_bare_name("{./apps/web}"));

        // Git refs (no)
        assert!(!looks_like_bare_name("[main]"));

        // Exclusions and closures (no)
        assert!(!looks_like_bare_name("!foo"));
        assert!(!looks_like_bare_name("foo..."));
        assert!(!looks_like_bare_name("...foo"));

        // Empty / whitespace (no)
        assert!(!looks_like_bare_name(""));
        assert!(!looks_like_bare_name("   "));
    }
}
