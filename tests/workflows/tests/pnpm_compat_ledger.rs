//! Consistency guard for `tests/PNPM_COMPAT.md`.
//!
//! The ledger is the reviewable map from pnpm source scenarios to LPM-owned
//! behavior contracts. This test keeps the table and the `pnpm_compat_*.rs`
//! workflow tests from drifting apart.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct LedgerRow {
    line: usize,
    lpm_test: String,
    status: String,
}

#[derive(Debug)]
struct TestInfo {
    file_name: String,
    line: usize,
    ignore_attr: Option<String>,
}

#[test]
fn pnpm_compat_ledger_matches_test_sources() {
    let ledger = parse_ledger(&ledger_path());
    let tests = collect_compat_tests(&test_source_dir());
    let mut errors = Vec::new();
    let mut ledger_tests = BTreeSet::new();

    if ledger.is_empty() {
        errors.push("tests/PNPM_COMPAT.md must contain at least one scenario row".to_string());
    }

    for row in &ledger {
        if row.status == "passing" || row.status.starts_with("blocked:") {
            if row.lpm_test == "-" {
                errors.push(format!(
                    "tests/PNPM_COMPAT.md:{} status `{}` must name a Rust test",
                    row.line, row.status
                ));
                continue;
            }
            ledger_tests.insert(row.lpm_test.clone());
            let Some(test) = tests.get(&row.lpm_test) else {
                errors.push(format!(
                    "tests/PNPM_COMPAT.md:{} references missing test `{}`",
                    row.line, row.lpm_test
                ));
                continue;
            };
            match row.status.as_str() {
                "passing" => {
                    if let Some(ignore_attr) = &test.ignore_attr {
                        errors.push(format!(
                            "{}:{} `{}` is marked passing but has {}",
                            test.file_name, test.line, row.lpm_test, ignore_attr
                        ));
                    }
                }
                status if status.starts_with("blocked:") => match &test.ignore_attr {
                    Some(ignore_attr) if ignore_attr.contains("blocked:") => {}
                    Some(ignore_attr) => errors.push(format!(
                        "{}:{} `{}` is `{}` but ignore attr is {}",
                        test.file_name, test.line, row.lpm_test, status, ignore_attr
                    )),
                    None => errors.push(format!(
                        "{}:{} `{}` is `{}` but is not ignored",
                        test.file_name, test.line, row.lpm_test, status
                    )),
                },
                _ => unreachable!("status shape checked by branch guard"),
            }
        } else if row.status.starts_with("wont-port:") {
            if row.lpm_test != "-" {
                errors.push(format!(
                    "tests/PNPM_COMPAT.md:{} `{}` must use `-` for wont-port rows",
                    row.line, row.status
                ));
            }
        } else {
            errors.push(format!(
                "tests/PNPM_COMPAT.md:{} has unsupported status `{}`",
                row.line, row.status
            ));
        }
    }

    for (test_name, test) in &tests {
        if !ledger_tests.contains(test_name) {
            errors.push(format!(
                "{}:{} `{test_name}` has no tests/PNPM_COMPAT.md row",
                test.file_name, test.line
            ));
        }
    }

    assert!(
        errors.is_empty(),
        "PNPM compat ledger drift:\n{}",
        errors.join("\n")
    );
}

fn workflow_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn ledger_path() -> PathBuf {
    workflow_root().join("..").join("PNPM_COMPAT.md")
}

fn test_source_dir() -> PathBuf {
    workflow_root().join("tests")
}

fn parse_ledger(path: &Path) -> Vec<LedgerRow> {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| parse_ledger_line(index + 1, line))
        .collect()
}

fn parse_ledger_line(line_number: usize, line: &str) -> Option<LedgerRow> {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
        return None;
    }
    let cells: Vec<String> = trimmed
        .trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect();
    if cells.len() != 6 {
        panic!(
            "tests/PNPM_COMPAT.md:{line_number} table rows must have 6 columns, got {}",
            cells.len()
        );
    }
    if cells[0].eq_ignore_ascii_case("area")
        || cells
            .iter()
            .all(|cell| cell.chars().all(|ch| ch == '-' || ch == ':'))
    {
        return None;
    }

    Some(LedgerRow {
        line: line_number,
        lpm_test: unquote_code_span(&cells[3]).to_string(),
        status: unquote_code_span(&cells[4]).to_string(),
    })
}

fn unquote_code_span(value: &str) -> &str {
    value
        .strip_prefix('`')
        .and_then(|inner| inner.strip_suffix('`'))
        .unwrap_or(value)
        .trim()
}

fn collect_compat_tests(source_dir: &Path) -> BTreeMap<String, TestInfo> {
    let mut tests = BTreeMap::new();
    for entry in std::fs::read_dir(source_dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", source_dir.display()))
    {
        let entry = entry.expect("failed to read workflow test directory entry");
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with("pnpm_compat_")
            || !file_name.ends_with(".rs")
            || file_name == "pnpm_compat_ledger.rs"
        {
            continue;
        }
        collect_tests_from_file(&path, file_name, &mut tests);
    }
    tests
}

fn collect_tests_from_file(path: &Path, file_name: &str, tests: &mut BTreeMap<String, TestInfo>) {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let mut saw_test_attr = false;
    let mut ignore_attr = None;

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[") {
            if trimmed.starts_with("#[test") || trimmed.starts_with("#[tokio::test") {
                saw_test_attr = true;
            }
            if trimmed.starts_with("#[ignore") {
                ignore_attr = Some(trimmed.to_string());
            }
            continue;
        }

        if let Some(test_name) = extract_fn_name(trimmed) {
            if saw_test_attr {
                let previous = tests.insert(
                    test_name.to_string(),
                    TestInfo {
                        file_name: file_name.to_string(),
                        line: index + 1,
                        ignore_attr: ignore_attr.take(),
                    },
                );
                assert!(
                    previous.is_none(),
                    "duplicate pnpm compat test function `{test_name}`"
                );
            }
            saw_test_attr = false;
            ignore_attr = None;
        }
    }
}

fn extract_fn_name(line: &str) -> Option<&str> {
    let fn_start = line.find("fn ")? + 3;
    let rest = &line[fn_start..];
    let name_end = rest
        .char_indices()
        .find_map(|(index, ch)| (!(ch == '_' || ch.is_ascii_alphanumeric())).then_some(index))
        .unwrap_or(rest.len());
    (name_end > 0).then_some(&rest[..name_end])
}
