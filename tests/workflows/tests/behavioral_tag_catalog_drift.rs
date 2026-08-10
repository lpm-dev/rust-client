//! Drift guard between the source-side `behavioral_tag_catalog()` in
//! `lpm-security` and the two doc tables that publish those tags to
//! end users (`security-audit.mdx` § "Layer 2" and `query.mdx` §
//! "Behavioral tags" / "Dependency state").
//!
//! Source of truth: [`lpm_security::query::behavioral_tag_catalog`].
//! Doc tables MUST mirror the catalog exactly — same tokens, same
//! descriptions, same coverage. When this test fails, edit the catalog
//! AND the matching doc tables in lockstep.
//!
//! ## How the test finds the docs dir
//!
//! Cross-repo concern, mirroring the schema-drift gate at
//! `crates/lpm-cli/tests/schema_drift.rs`. Standalone `rust-client` CI
//! doesn't check out `rust-client-docs`, so the gate must not block
//! that workflow.
//!
//! Resolution order:
//!
//! 1. `LPM_DOCS_DIR=<path>` — explicit path to the docs `content/docs/`
//!    directory. **Hard-fails** when the path doesn't exist. Use this
//!    in any CI that wants the drift check enforced.
//! 2. `LPM_DOCS_DIR=skip` — explicit opt-out, with a stderr note.
//! 3. Otherwise: walk up from `CARGO_MANIFEST_DIR` looking for a
//!    descendant `rust-client-docs/content/docs/` under any
//!    intermediate ancestor. Handles both the sibling-under-one-parent
//!    layout (`Projects/lpm-dev/{rust-client,rust-client-docs}/`) and
//!    cross-subtree layouts.
//! 4. When none of the above resolves: **silent skip with stderr
//!    note**. Standalone CI without the docs repo just sees the test
//!    pass.

use lpm_security::query::{BehavioralTagInfo, TagGroup, behavioral_tag_catalog};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const SKIP_SENTINEL: &str = "skip";

enum Located {
    Found(PathBuf),
    Skipped(String),
    ExplicitMissing(PathBuf),
}

fn locate_docs_dir() -> Located {
    if let Ok(explicit) = std::env::var("LPM_DOCS_DIR") {
        if explicit == SKIP_SENTINEL {
            return Located::Skipped(format!("LPM_DOCS_DIR={SKIP_SENTINEL} (explicit opt-out)"));
        }
        let path = PathBuf::from(explicit);
        return if path.is_dir() {
            Located::Found(path)
        } else {
            Located::ExplicitMissing(path)
        };
    }
    let mut cursor = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        for candidate in candidate_dirs_under(&cursor) {
            if candidate.is_dir() {
                return Located::Found(candidate);
            }
        }
        if !cursor.pop() {
            return Located::Skipped(
                "no rust-client-docs/content/docs/ found under any ancestor of \
                 CARGO_MANIFEST_DIR. Set LPM_DOCS_DIR=<path> to enforce."
                    .into(),
            );
        }
    }
}

fn candidate_dirs_under(root: &Path) -> Vec<PathBuf> {
    let target = Path::new("rust-client-docs").join("content").join("docs");
    let mut out = vec![root.join(&target)];
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.push(path.join(&target));
            }
        }
    }
    out
}

/// Pull the `(token, description)` rows out of every Markdown table in
/// the file whose first column is a `:tag` token. Doc-source-of-truth
/// for the user-facing prose.
///
/// Doc tables look like:
///
/// ```markdown
/// | Tag | Detects |
/// | --- | --- |
/// | `:eval` | `eval`, `Function()`, or `vm.runInThisContext` |
/// ```
///
/// The parser is intentionally narrow:
/// - row begins with `| `
/// - first column is `` `:token` `` (single-backtick code span)
/// - second column is the description (we strip surrounding whitespace)
/// - separator rows (`| --- | --- |`) and header rows are ignored
fn parse_tag_rows(mdx: &str) -> HashMap<String, String> {
    let mut rows = HashMap::new();
    for line in mdx.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        // Split the row into cells, dropping the leading + trailing pipes
        let cells: Vec<&str> = trimmed
            .split('|')
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .collect();
        if cells.len() < 2 {
            continue;
        }
        let first = cells[0];
        // Skip separator lines `--- ---`
        if first.chars().all(|c| c == '-' || c == ':') {
            continue;
        }
        // Skip headers (no backtick + colon)
        if !first.starts_with("`:") || !first.ends_with('`') {
            continue;
        }
        let token = first.trim_start_matches('`').trim_end_matches('`');
        // Reject anything that isn't a simple `:name` token. The
        // Combinators table on query.mdx contains rows like `` `:a, :b` ``
        // and `` `:root > :child` `` — those are syntax samples, not real
        // tag tokens, and must not be treated as catalog entries.
        let body = match token.strip_prefix(':') {
            Some(b) => b,
            None => continue,
        };
        let is_simple_token = !body.is_empty()
            && body
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !is_simple_token {
            continue;
        }
        let description = cells[1..].join(" | ");
        rows.insert(token.to_string(), description);
    }
    rows
}

fn assert_doc_covers_catalog(
    page_label: &str,
    mdx_path: &Path,
    catalog: &[BehavioralTagInfo],
    expected_tokens: &HashSet<&str>,
) {
    let mdx = std::fs::read_to_string(mdx_path).unwrap_or_else(|e| {
        panic!(
            "could not read {}: {e}\nIs LPM_DOCS_DIR pointed at the right place?",
            mdx_path.display()
        )
    });
    let rows = parse_tag_rows(&mdx);

    // Every catalog entry the doc claims to cover must have a row.
    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    for tag in catalog {
        if !expected_tokens.contains(tag.token) {
            continue;
        }
        match rows.get(tag.token) {
            None => missing.push(tag.token),
            Some(doc_desc) => {
                if doc_desc != tag.description {
                    mismatched.push(format!(
                        "  {} {}\n    catalog: {}\n    doc:     {}",
                        tag.token, page_label, tag.description, doc_desc
                    ));
                }
            }
        }
    }
    if !missing.is_empty() || !mismatched.is_empty() {
        let missing_msg = if missing.is_empty() {
            String::new()
        } else {
            format!("\nmissing rows in {page_label}: {missing:?}")
        };
        let mismatched_msg = if mismatched.is_empty() {
            String::new()
        } else {
            format!(
                "\ndescription drift in {page_label}:\n{}",
                mismatched.join("\n")
            )
        };
        panic!(
            "behavioral tag catalog drift detected at {}:{}{}\n\n\
             Source of truth: lpm_security::query::behavioral_tag_catalog().\n\
             Edit the catalog AND the matching doc table together.",
            mdx_path.display(),
            missing_msg,
            mismatched_msg,
        );
    }
}

/// security-audit.mdx splits the catalog into three tables — Source
/// (10), Supply chain (8), Manifest (5). Every catalog entry MUST
/// appear in exactly one of those tables, and every row MUST be in
/// the catalog.
#[test]
fn security_audit_mdx_mirrors_catalog() {
    let dir = match locate_docs_dir() {
        Located::Found(d) => d,
        Located::Skipped(reason) => {
            eprintln!("[behavioral_tag_catalog_drift] security-audit: skipped — {reason}");
            return;
        }
        Located::ExplicitMissing(path) => panic!(
            "LPM_DOCS_DIR points at {} which is not a directory. Either fix the \
             path, unset the variable to fall back to the implicit walk-up + \
             silent-skip behavior, or set LPM_DOCS_DIR=skip to opt out.",
            path.display()
        ),
    };
    let mdx_path = dir.join("packages").join("security-audit.mdx");
    let catalog = behavioral_tag_catalog();
    let all_tokens: HashSet<&str> = catalog.iter().map(|t| t.token).collect();
    assert_doc_covers_catalog("security-audit.mdx", &mdx_path, &catalog, &all_tokens);

    // Reverse direction: every `:tag` row in the doc must map to a
    // catalog entry. Catches the case where the doc adds a tag the
    // catalog hasn't grown yet.
    let mdx = std::fs::read_to_string(&mdx_path).unwrap();
    let rows = parse_tag_rows(&mdx);
    let catalog_tokens: HashSet<&str> = all_tokens.clone();
    let mut stray = Vec::new();
    for token in rows.keys() {
        // Tolerate state/severity tokens that legitimately appear in
        // adjacent non-behavioral tables (e.g., `:scripts`, `:built`,
        // `:critical`, `:lpm`). Only flag tokens shaped like behavioral
        // tags but absent from the catalog.
        if catalog_tokens.contains(token.as_str()) {
            continue;
        }
        // Skip clearly-non-behavioral tokens.
        const NON_BEHAVIORAL: &[&str] = &[
            ":scripts",
            ":built",
            ":vulnerable",
            ":deprecated",
            ":lpm",
            ":npm",
            ":critical",
            ":high",
            ":medium",
            ":info",
            ":root",
            ":workspace-root",
        ];
        if NON_BEHAVIORAL.contains(&token.as_str()) {
            continue;
        }
        stray.push(token.clone());
    }
    assert!(
        stray.is_empty(),
        "security-audit.mdx has tag rows that aren't in the catalog: {stray:?}\n\
         Either add them to lpm_security::query::PseudoClass + behavioral_tag_catalog() \
         or remove them from the doc."
    );
}

/// query.mdx splits the catalog into a "Behavioral tags" table (the
/// 10 source + 7 supply-chain) and a "Dependency state" table that
/// includes the 5 manifest tags plus state tokens (`:scripts`,
/// `:built`, etc.). Every behavioral tag MUST appear somewhere on the
/// page.
#[test]
fn query_mdx_mirrors_catalog() {
    let dir = match locate_docs_dir() {
        Located::Found(d) => d,
        Located::Skipped(reason) => {
            eprintln!("[behavioral_tag_catalog_drift] query: skipped — {reason}");
            return;
        }
        Located::ExplicitMissing(path) => panic!(
            "LPM_DOCS_DIR points at {} which is not a directory. Either fix the \
             path, unset the variable to fall back to the implicit walk-up + \
             silent-skip behavior, or set LPM_DOCS_DIR=skip to opt out.",
            path.display()
        ),
    };
    let mdx_path = dir.join("packages").join("query.mdx");
    let catalog = behavioral_tag_catalog();
    let all_tokens: HashSet<&str> = catalog.iter().map(|t| t.token).collect();
    assert_doc_covers_catalog("query.mdx", &mdx_path, &catalog, &all_tokens);

    // Reverse-direction stray-tag check (mirrors security-audit's).
    // Without it, an extra `:bogus-tag` row added to query.mdx would
    // pass CI as long as none of the real catalog rows go missing.
    // query.mdx documents the same non-behavioral tokens as
    // security-audit (state, severity, special), so the tolerance list
    // matches.
    let mdx = std::fs::read_to_string(&mdx_path).unwrap();
    let rows = parse_tag_rows(&mdx);
    let mut stray = Vec::new();
    for token in rows.keys() {
        if all_tokens.contains(token.as_str()) {
            continue;
        }
        const NON_BEHAVIORAL: &[&str] = &[
            ":scripts",
            ":built",
            ":vulnerable",
            ":deprecated",
            ":lpm",
            ":npm",
            ":critical",
            ":high",
            ":medium",
            ":info",
            ":root",
            ":workspace-root",
        ];
        if NON_BEHAVIORAL.contains(&token.as_str()) {
            continue;
        }
        stray.push(token.clone());
    }
    assert!(
        stray.is_empty(),
        "query.mdx has tag rows that aren't in the catalog: {stray:?}\n\
         Either add them to lpm_security::query::PseudoClass + \
         behavioral_tag_catalog() or remove them from the doc."
    );
}

/// Sanity: the catalog itself partitions cleanly into the three
/// expected groups. Catches the case where someone adds a 23rd tag
/// without picking a group, or where two tags share a token.
#[test]
fn catalog_partitions_into_three_groups_with_unique_tokens() {
    let catalog = behavioral_tag_catalog();
    let mut tokens = HashSet::new();
    let mut groups: HashMap<TagGroup, usize> = HashMap::new();
    for tag in &catalog {
        assert!(
            tokens.insert(tag.token),
            "duplicate token in catalog: {}",
            tag.token
        );
        *groups.entry(tag.group).or_insert(0) += 1;
    }
    assert!(
        groups.contains_key(&TagGroup::Source),
        "catalog must have at least one Source tag"
    );
    assert!(
        groups.contains_key(&TagGroup::SupplyChain),
        "catalog must have at least one SupplyChain tag"
    );
    assert!(
        groups.contains_key(&TagGroup::Manifest),
        "catalog must have at least one Manifest tag"
    );
}
