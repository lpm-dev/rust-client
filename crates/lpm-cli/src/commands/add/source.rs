use lpm_common::LpmError;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub(super) fn is_runtime_source_text_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if file_name.ends_with(".d.ts")
        || file_name.ends_with(".d.cts")
        || file_name.ends_with(".d.mts")
    {
        return false;
    }

    matches!(
        path.extension().and_then(|e| e.to_str()).unwrap_or(""),
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs"
    )
}

/// Read lpm.config.json from extracted package.
pub(super) fn read_lpm_config(extract_dir: &Path) -> Result<Option<serde_json::Value>, LpmError> {
    let path = extract_dir.join("lpm.config.json");
    let content =
        match lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    serde_json::from_str(&content)
        .map(Some)
        .map_err(|error| LpmError::Registry(format!("failed to parse {}: {error}", path.display())))
}

/// Coerce a JSON value from `lpm.config.json` to its canonical string
/// form for the inline-config map.
///
/// `inline_config` stores every field value as a string (booleans are
/// `"true"` / `"false"`, numbers stringified) so the downstream
/// substitution + condition-eval paths can treat all values uniformly.
/// This helper mirrors that contract.
///
/// Accepts the natural authored form (`true`, `42`) AND the legacy
/// stringified form (`"true"`, `"42"`) for back-compat with packages
/// whose `lpm.config.json` was authored against the older string-only
/// reader. Returns `None` for nulls / arrays / objects, which aren't
/// valid leaf values in this surface.
pub(super) fn json_value_to_config_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Filter files using lpm.config.json `files` array with condition evaluation.
pub(super) fn filter_config_files(
    extract_dir: &Path,
    files_rules: &[serde_json::Value],
    config: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let provided_params: HashSet<&str> = config.keys().map(|k| k.as_str()).collect();
    let mut result = Vec::new();

    for rule in files_rules {
        let src_pattern = rule.get("src").and_then(|v| v.as_str()).unwrap_or("");
        let dest = rule
            .get("dest")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let include = rule
            .get("include")
            .and_then(|v| v.as_str())
            .unwrap_or("always");

        // Evaluate condition
        match include {
            "never" => continue,
            "when" => {
                if let Some(condition) = rule.get("condition").and_then(|c| c.as_object()) {
                    let mut matches = true;
                    for (key, expected) in condition {
                        // If the key wasn't explicitly provided, include the file (all-by-default)
                        if !provided_params.contains(key.as_str()) {
                            continue;
                        }
                        // Coerce native JSON values (`true`, `42`) to
                        // their canonical string form so authors can use
                        // the natural authored type. Falls back to "" for
                        // null/array/object — same semantics as the
                        // legacy string-only path.
                        let expected_str =
                            json_value_to_config_string(expected).unwrap_or_default();
                        let actual = config.get(key).map_or("", |s| s.as_str());

                        // Support comma-separated multi-select
                        if !actual.split(',').any(|x| x == expected_str.as_str()) {
                            matches = false;
                            break;
                        }
                    }
                    if !matches {
                        continue;
                    }
                }
            }
            _ => {} // "always" or missing -- include
        }

        // Expand src pattern to actual file paths
        let expanded = expand_src_pattern(extract_dir, src_pattern);

        // Compute the base directory of the src pattern (strip trailing /** or /*)
        let pattern_base = src_pattern.trim_end_matches("/**").trim_end_matches("/*");

        let multi_file = expanded.len() > 1;
        for path in expanded {
            if !path.is_file() {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(extract_dir) {
                let src_rel = rel.to_string_lossy().to_string();
                let dest_rel = if let Some(d) = &dest {
                    if d.ends_with('/') {
                        format!(
                            "{}{}",
                            d,
                            rel.file_name().unwrap_or_default().to_string_lossy()
                        )
                    } else if multi_file {
                        // Multiple files: maintain structure relative to glob base
                        // JS CLI: path.relative(baseSrc, srcFile) then path.join(dest, relFromBase)
                        let base_path = extract_dir.join(pattern_base);
                        let rel_from_base = path.strip_prefix(&base_path).unwrap_or(rel);
                        format!(
                            "{}/{}",
                            d.trim_end_matches('/'),
                            rel_from_base.to_string_lossy()
                        )
                    } else {
                        d.clone()
                    }
                } else {
                    src_rel.clone()
                };
                result.push((src_rel, dest_rel));
            }
        }
    }

    result
}

/// Expand a src pattern from lpm.config.json to actual file paths.
///
/// Matches the JS CLI's `expandSrcGlob` behaviour:
///   - Exact paths: `"lib/utils.js"` → check existence
///   - Recursive wildcard: `"components/dialog/**"` → walk directory tree
///   - Single-dir wildcard: `"styles/*.css"` → regex match in one directory
///
/// The `glob` crate's `**` only matches directories, NOT files, so we must
/// handle `/**` ourselves with a recursive walk (same as the JS CLI does).
fn expand_src_pattern(extract_dir: &Path, pattern: &str) -> Vec<PathBuf> {
    // No wildcard → exact path check
    if !pattern.contains('*') {
        let full_path = extract_dir.join(pattern);
        if full_path.exists() {
            return vec![full_path];
        }
        return vec![];
    }

    // Recursive wildcard: "dir/**"
    if let Some(base) = pattern.strip_suffix("/**") {
        // strip "/**"
        let base_dir = extract_dir.join(base);
        if !base_dir.is_dir() {
            return vec![];
        }
        let mut results = Vec::new();
        collect_files_recursive(&base_dir, &mut results);
        return results;
    }

    // Single-directory wildcard: "dir/*.ext" or "*.md"
    let last_slash = pattern.rfind('/');
    let (dir_part, file_part) = match last_slash {
        Some(pos) => (&pattern[..pos], &pattern[pos + 1..]),
        None => (".", pattern),
    };

    if file_part.contains('*') {
        let full_dir = if dir_part == "." {
            extract_dir.to_path_buf()
        } else {
            extract_dir.join(dir_part)
        };
        if !full_dir.is_dir() {
            return vec![];
        }

        let mut results = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&full_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && glob_simple_match(file_part, name)
                {
                    results.push(path);
                }
            }
        }
        return results;
    }

    // Fallback: treat as exact path
    let full_path = extract_dir.join(pattern);
    if full_path.exists() {
        vec![full_path]
    } else {
        vec![]
    }
}

/// Match a filename against a simple glob pattern (supports `*` only).
///
/// Examples: `"*.css"` matches `"style.css"`, `"*.*"` matches `"foo.bar"`.
fn glob_simple_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Split pattern on '*' and check that all parts appear in order
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return pattern == name;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // First part must be a prefix
            if !name.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Last part must be a suffix
            if !name[pos..].ends_with(part) {
                return false;
            }
            pos = name.len();
        } else {
            match name[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// Recursively collect all files in a directory.
fn collect_files_recursive(dir: &Path, results: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, results);
        } else if path.is_file() {
            results.push(path);
        }
    }
}

/// Collect source files, checking package.json#lpm.source first (legacy fallback),
/// then falling back to all files in the extraction directory.
pub(super) fn collect_source_with_fallback(
    extract_dir: &Path,
) -> Result<Vec<(String, String)>, LpmError> {
    // Check package.json for lpm.source field (legacy packages)
    let pkg_json_path = extract_dir.join("package.json");
    if let Ok(content) =
        lpm_common::read_text_file_capped(&pkg_json_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        && let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content)
        && let Some(source_dir) = doc
            .get("lpm")
            .and_then(|l| l.get("source"))
            .and_then(|s| s.as_str())
    {
        let source_path = extract_dir.join(source_dir);
        if source_path.is_dir() {
            let mut files = Vec::new();
            collect_dir_no_skip(&source_path, &source_path, &mut files)?;
            if !files.is_empty() {
                return Ok(files);
            }
        } else if source_path.is_file() {
            // Single file source
            let name = source_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            return Ok(vec![(name.clone(), name)]);
        }
    }

    // Fall back to collecting all source files
    collect_all_source_files(extract_dir)
}

/// Collect files from a directory without the node_modules/test skip list.
/// Used for lpm.source directories where we want everything.
fn collect_dir_no_skip(
    dir: &Path,
    root: &Path,
    files: &mut Vec<(String, String)>,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir_no_skip(&path, root, files)?;
        } else if path.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            let rel_str = rel.to_string_lossy().to_string();
            files.push((rel_str.clone(), rel_str));
        }
    }
    Ok(())
}

/// Collect all files from extracted package (fallback when no config).
fn collect_all_source_files(extract_dir: &Path) -> Result<Vec<(String, String)>, LpmError> {
    let mut files = Vec::new();
    collect_dir(extract_dir, extract_dir, &mut files)?;
    Ok(files)
}

fn collect_dir(dir: &Path, root: &Path, files: &mut Vec<(String, String)>) -> Result<(), LpmError> {
    static SKIP: &[&str] = &["node_modules", ".git", "__tests__", "test", "tests"];

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            if SKIP.contains(&name_str.as_ref()) {
                continue;
            }
            collect_dir(&path, root, files)?;
        } else if path.is_file() {
            if name_str == "package.json" || name_str == "lpm.config.json" {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(root) {
                let rel_str = rel.to_string_lossy().to_string();
                files.push((rel_str.clone(), rel_str));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // ── lpm.config.json value coercion (json_value_to_config_string) ───
    //
    // The wire contract for `lpm.config.json` accepts both the natural
    // authored form (JSON booleans, numbers) AND the legacy stringified
    // form (`"true"`, `"42"`). The schema published at
    // `https://cli.lpm.dev/schemas/lpm.config.json` declares booleans
    // natively, so the runtime MUST accept both forms or the schema and
    // the runtime would disagree on whether `"default": true` is valid.
    //
    // These tests pin the contract at the helper level so a regression
    // in any of the three call sites (interactive prompt default, --yes
    // required-field default, files[].condition value) gets caught.

    mod config_value_coercion {
        use super::super::*;
        use serde_json::json;

        #[test]
        fn native_boolean_true_to_string() {
            assert_eq!(
                json_value_to_config_string(&json!(true)),
                Some("true".into())
            );
        }

        #[test]
        fn native_boolean_false_to_string() {
            assert_eq!(
                json_value_to_config_string(&json!(false)),
                Some("false".into())
            );
        }

        #[test]
        fn legacy_string_true_passes_through() {
            // Back-compat: packages authored against the older
            // string-only reader continue to work. `"true"` (quoted)
            // and `true` (bare) must produce identical inline-config
            // values.
            assert_eq!(
                json_value_to_config_string(&json!("true")),
                Some("true".into())
            );
        }

        #[test]
        fn legacy_string_false_passes_through() {
            assert_eq!(
                json_value_to_config_string(&json!("false")),
                Some("false".into())
            );
        }

        #[test]
        fn integer_to_string() {
            // Numeric defaults (e.g., `"default": 42` for a port) get
            // stringified — same shape as inline-config values.
            assert_eq!(json_value_to_config_string(&json!(42)), Some("42".into()));
        }

        #[test]
        fn arbitrary_string_passes_through() {
            assert_eq!(
                json_value_to_config_string(&json!("dialog")),
                Some("dialog".into())
            );
        }

        #[test]
        fn null_returns_none() {
            assert_eq!(json_value_to_config_string(&json!(null)), None);
        }

        #[test]
        fn array_returns_none() {
            // Arrays aren't valid leaf values in this surface — a
            // multi-select default uses a comma-joined string per
            // existing convention.
            assert_eq!(json_value_to_config_string(&json!(["a", "b"])), None);
        }

        #[test]
        fn object_returns_none() {
            assert_eq!(json_value_to_config_string(&json!({"x": 1})), None);
        }
    }

    // ── filter_config_files: condition-eval coercion regression ──────
    //
    // `condition` map values must accept both native JSON booleans and
    // legacy string forms. Reading only string values would turn
    // `condition: {includeTests: true}` into `""` and fail to match the
    // inline-config value `"true"`.

    mod filter_config_files_condition {
        use super::super::*;
        use serde_json::json;
        use std::collections::HashMap;

        fn make_extract_dir() -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            // Create a few files so src patterns resolve.
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::write(dir.path().join("src/index.ts"), "// index").unwrap();
            std::fs::write(dir.path().join("src/test.ts"), "// test").unwrap();
            dir
        }

        fn config(pairs: &[(&str, &str)]) -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        }

        #[test]
        fn native_boolean_condition_true_matches_string_true() {
            // Author writes `"condition": {"withTests": true}` (native
            // JSON bool). User opted in, so inline_config has
            // "withTests" → "true". Rule must match → file included.
            let dir = make_extract_dir();
            let rules = vec![json!({
                "src": "src/test.ts",
                "include": "when",
                "condition": {"withTests": true},
            })];
            let out = filter_config_files(dir.path(), &rules, &config(&[("withTests", "true")]));
            assert_eq!(out.len(), 1, "native-bool condition must match: {out:?}");
        }

        #[test]
        fn native_boolean_condition_true_excludes_string_false() {
            let dir = make_extract_dir();
            let rules = vec![json!({
                "src": "src/test.ts",
                "include": "when",
                "condition": {"withTests": true},
            })];
            let out = filter_config_files(dir.path(), &rules, &config(&[("withTests", "false")]));
            assert!(out.is_empty(), "must exclude on opposite value: {out:?}");
        }

        #[test]
        fn legacy_string_condition_still_matches() {
            // Back-compat: packages authored against the older
            // string-only reader continue to work.
            let dir = make_extract_dir();
            let rules = vec![json!({
                "src": "src/test.ts",
                "include": "when",
                "condition": {"withTests": "true"},
            })];
            let out = filter_config_files(dir.path(), &rules, &config(&[("withTests", "true")]));
            assert_eq!(out.len(), 1, "legacy string condition must match: {out:?}");
        }

        #[test]
        fn condition_skipped_when_param_not_provided() {
            // Pre-existing "all-by-default" semantic: if the user didn't
            // supply the param at all, the file is included. This test
            // pins that contract isn't broken by the coercion fix.
            let dir = make_extract_dir();
            let rules = vec![json!({
                "src": "src/test.ts",
                "include": "when",
                "condition": {"withTests": true},
            })];
            let out = filter_config_files(dir.path(), &rules, &HashMap::new());
            assert_eq!(
                out.len(),
                1,
                "missing param must include the file (all-by-default): {out:?}",
            );
        }
    }
}
