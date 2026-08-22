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
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts"
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
    crate::lpm_config::parse_and_validate(&path, &content).map(Some)
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

pub(super) fn resolve_noninteractive_required_config(
    config: &serde_json::Value,
    values: &mut HashMap<String, String>,
) -> Result<(), LpmError> {
    let Some(schema) = config
        .get("configSchema")
        .and_then(|value| value.as_object())
    else {
        return Ok(());
    };
    for (key, field) in schema {
        if values.contains_key(key) {
            continue;
        }
        let required = field
            .get("required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let resolved = config
            .get("defaultConfig")
            .and_then(|defaults| defaults.get(key))
            .and_then(json_value_to_config_string)
            .or_else(|| field.get("default").and_then(json_value_to_config_string))
            .or_else(|| {
                if !required {
                    return None;
                }
                (field.get("type").and_then(serde_json::Value::as_str) == Some("boolean"))
                    .then(|| "false".to_string())
            })
            .or_else(|| {
                if !required {
                    return None;
                }
                let options = field.get("options")?.as_array()?;
                (options.len() == 1).then(|| {
                    options[0]
                        .as_str()
                        .or_else(|| options[0].get("value").and_then(serde_json::Value::as_str))
                        .map(str::to_string)
                })?
            });
        if let Some(value) = resolved.filter(|value| !value.is_empty()) {
            values.insert(key.clone(), value);
        } else if required {
            return Err(LpmError::Registry(format!(
                "required configuration '{key}' has no default; provide it in the package spec as '?{key}=value'"
            )));
        }
    }
    validate_declared_config_values(config, values)
}

pub(super) fn validate_declared_config_values(
    config: &serde_json::Value,
    values: &mut HashMap<String, String>,
) -> Result<(), LpmError> {
    let Some(schema) = config
        .get("configSchema")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    for key in values.keys() {
        if !schema.contains_key(key) {
            return Err(LpmError::Registry(format!(
                "configuration '{key}' is not declared by this package"
            )));
        }
    }

    let mut unset = Vec::new();
    for (key, value) in values.iter_mut() {
        let field = &schema[key];
        let required = field
            .get("required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let field_type = field
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("string");
        if value.is_empty() {
            if required {
                return Err(LpmError::Registry(format!(
                    "required configuration '{key}' cannot be empty"
                )));
            }
            unset.push(key.clone());
            continue;
        }

        match field_type {
            "boolean" if value != "true" && value != "false" => {
                return Err(LpmError::Registry(format!(
                    "configuration '{key}' must be 'true' or 'false', got '{value}'"
                )));
            }
            "select" => {
                let options = field
                    .get("options")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|option| {
                        option
                            .as_str()
                            .or_else(|| option.get("value").and_then(serde_json::Value::as_str))
                    })
                    .collect::<HashSet<_>>();
                let multi = field
                    .get("multiSelect")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                let selections = value.split(',').map(str::trim).collect::<Vec<_>>();
                if !multi && selections.len() != 1 {
                    return Err(LpmError::Registry(format!(
                        "configuration '{key}' accepts one selection"
                    )));
                }
                if let Some(invalid) = selections
                    .iter()
                    .find(|selection| selection.is_empty() || !options.contains(**selection))
                {
                    return Err(LpmError::Registry(format!(
                        "configuration '{key}' has invalid selection '{invalid}'"
                    )));
                }
                if multi {
                    *value = selections.join(",");
                }
            }
            _ => {}
        }
    }
    for key in unset {
        values.remove(&key);
    }
    Ok(())
}

/// Filter files using lpm.config.json `files` array with condition evaluation.
pub(super) fn filter_config_files(
    extract_dir: &Path,
    files_rules: &[serde_json::Value],
    config: &HashMap<String, String>,
) -> Result<Vec<(String, String)>, LpmError> {
    let provided_params: HashSet<&str> = config.keys().map(|k| k.as_str()).collect();
    let mut result = Vec::new();
    let source_index = index_source_files(extract_dir)?;

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
        validate_source_selector(src_pattern)?;
        let src_pattern = normalize_logical_path(src_pattern);
        let expanded = expand_src_pattern(&source_index, &src_pattern);

        // Compute the base directory of the src pattern (strip trailing /** or /*)
        let pattern_base = src_pattern.trim_end_matches("/**").trim_end_matches("/*");

        let multi_file = expanded.len() > 1;
        for (path, src_rel) in expanded {
            let dest_rel = if let Some(d) = &dest {
                if d.ends_with('/') {
                    format!(
                        "{}{}",
                        d,
                        path.file_name().unwrap_or_default().to_string_lossy()
                    )
                } else if multi_file {
                    // Matches the JS CLI's range-target directory layout.
                    let rel_from_base = src_rel
                        .strip_prefix(pattern_base)
                        .and_then(|value| value.strip_prefix('/'))
                        .unwrap_or(&src_rel);
                    format!("{}/{}", d.trim_end_matches('/'), rel_from_base)
                } else {
                    d.clone()
                }
            } else {
                src_rel.clone()
            };
            result.push((src_rel, dest_rel));
        }
    }

    Ok(result)
}

struct IndexedSourceFile {
    absolute: PathBuf,
    logical: String,
}

fn normalize_logical_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn validate_source_selector(pattern: &str) -> Result<(), LpmError> {
    let path = Path::new(pattern);
    if pattern.is_empty() || path.is_absolute() {
        return Err(LpmError::Registry(format!(
            "source selector '{pattern}' must be a non-empty relative path"
        )));
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err(LpmError::Registry(format!(
            "source selector '{pattern}' contains a parent, root, or drive component"
        )));
    }
    Ok(())
}

fn index_source_files(extract_dir: &Path) -> Result<Vec<IndexedSourceFile>, LpmError> {
    fn visit(
        extract_dir: &Path,
        dir: &Path,
        files: &mut Vec<IndexedSourceFile>,
    ) -> Result<(), LpmError> {
        let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_unstable_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                visit(extract_dir, &path, files)?;
            } else if metadata.is_file()
                && let Ok(relative) = path.strip_prefix(extract_dir)
            {
                let logical = normalize_logical_path(&relative.to_string_lossy());
                files.push(IndexedSourceFile {
                    absolute: path,
                    logical,
                });
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(extract_dir, extract_dir, &mut files)?;
    Ok(files)
}

fn expand_src_pattern<'a>(
    files: &'a [IndexedSourceFile],
    pattern: &str,
) -> Vec<(&'a Path, String)> {
    if !pattern.contains('*') {
        return files
            .iter()
            .filter(|file| file.logical == pattern)
            .map(|file| (file.absolute.as_path(), file.logical.clone()))
            .collect();
    }

    if let Some(base) = pattern.strip_suffix("/**") {
        let prefix = format!("{}/", base.trim_end_matches('/'));
        return files
            .iter()
            .filter(|file| file.logical.starts_with(&prefix))
            .map(|file| (file.absolute.as_path(), file.logical.clone()))
            .collect();
    }

    // Single-directory wildcard: "dir/*.ext" or "*.md"
    let last_slash = pattern.rfind('/');
    let (dir_part, file_part) = match last_slash {
        Some(pos) => (&pattern[..pos], &pattern[pos + 1..]),
        None => (".", pattern),
    };

    if file_part.contains('*') {
        return files
            .iter()
            .filter(|file| {
                let (file_dir, name) = file
                    .logical
                    .rsplit_once('/')
                    .map_or((".", file.logical.as_str()), |(dir, name)| (dir, name));
                file_dir == dir_part && glob_simple_match(file_part, name)
            })
            .map(|file| (file.absolute.as_path(), file.logical.clone()))
            .collect();
    }

    // Fallback: treat as exact path
    Vec::new()
}

/// Match a filename against a simple glob pattern (supports `*` only).
///
/// Examples: `"*.css"` matches `"style.css"`, `"*.*"` matches `"foo.bar"`.
fn glob_simple_match(pattern: &str, name: &str) -> bool {
    let pattern = pattern.as_bytes();
    let name = name.as_bytes();
    let (mut p, mut n, mut star, mut retry) = (0, 0, None, 0);
    while n < name.len() {
        if p < pattern.len() && pattern[p] == name[n] {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = n;
        } else if let Some(star_index) = star {
            retry += 1;
            n = retry;
            p = star_index + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
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
        validate_source_selector(source_dir)?;
        let source_path = extract_dir.join(source_dir);
        let source_path = source_path.canonicalize().map_err(|error| {
            LpmError::Registry(format!("invalid lpm.source '{source_dir}': {error}"))
        })?;
        let extract_canonical = extract_dir.canonicalize()?;
        if !source_path.starts_with(&extract_canonical) {
            return Err(LpmError::Registry(format!(
                "lpm.source '{source_dir}' resolves outside the extracted package"
            )));
        }
        if source_path.is_dir() {
            let mut files = Vec::new();
            collect_dir_no_skip(&source_path, &extract_canonical, &source_path, &mut files)?;
            if !files.is_empty() {
                files.sort_unstable_by(|left, right| left.0.cmp(&right.0));
                return Ok(files);
            }
        } else if source_path.is_file() {
            // Single file source
            let name = source_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let src = source_path
                .strip_prefix(&extract_canonical)
                .map(|path| normalize_logical_path(&path.to_string_lossy()))
                .map_err(|_| LpmError::Registry("lpm.source escaped extraction".into()))?;
            return Ok(vec![(src, name)]);
        }
    }

    // Fall back to collecting all source files
    collect_all_source_files(extract_dir)
}

/// Collect files from a directory without the node_modules/test skip list.
/// Used for lpm.source directories where we want everything.
fn collect_dir_no_skip(
    dir: &Path,
    extract_root: &Path,
    dest_root: &Path,
    files: &mut Vec<(String, String)>,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_dir_no_skip(&path, extract_root, dest_root, files)?;
        } else if metadata.is_file()
            && let (Ok(src_rel), Ok(dest_rel)) = (
                path.strip_prefix(extract_root),
                path.strip_prefix(dest_root),
            )
        {
            files.push((
                normalize_logical_path(&src_rel.to_string_lossy()),
                normalize_logical_path(&dest_rel.to_string_lossy()),
            ));
        }
    }
    Ok(())
}

/// Collect all files from extracted package (fallback when no config).
fn collect_all_source_files(extract_dir: &Path) -> Result<Vec<(String, String)>, LpmError> {
    let mut files = Vec::new();
    collect_dir(extract_dir, extract_dir, &mut files)?;
    files.sort_unstable_by(|left, right| left.0.cmp(&right.0));
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
                let rel_str = normalize_logical_path(&rel.to_string_lossy());
                files.push((rel_str.clone(), rel_str));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_source_detection_includes_modern_typescript_modules() {
        for path in ["module.mts", "module.cts"] {
            assert!(is_runtime_source_text_file(Path::new(path)), "{path}");
        }
        for path in ["module.d.mts", "module.d.cts"] {
            assert!(!is_runtime_source_text_file(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn fallback_source_collection_is_lexically_ordered() {
        let extract = tempfile::tempdir().unwrap();
        std::fs::write(extract.path().join("z.ts"), "z").unwrap();
        std::fs::create_dir(extract.path().join("z-dir")).unwrap();
        std::fs::write(extract.path().join("z-dir/b.ts"), "b").unwrap();
        std::fs::write(extract.path().join("a.ts"), "a").unwrap();
        std::fs::create_dir(extract.path().join("a-dir")).unwrap();
        std::fs::write(extract.path().join("a-dir/c.ts"), "c").unwrap();

        let files = collect_all_source_files(extract.path()).unwrap();
        let paths = files
            .into_iter()
            .map(|(source, _)| source)
            .collect::<Vec<_>>();

        assert_eq!(paths, ["a-dir/c.ts", "a.ts", "z-dir/b.ts", "z.ts"]);
    }

    #[test]
    fn noninteractive_config_rejects_values_outside_the_declared_schema() {
        let config = json!({
            "configSchema": {
                "enabled": {"type": "boolean"},
                "variant": {"type": "select", "options": ["a", "b"]},
                "features": {"type": "select", "multiSelect": true, "options": ["x", "y"]}
            }
        });
        for (key, value) in [
            ("enabled", "maybe"),
            ("variant", "unknown"),
            ("features", "x,unknown"),
            ("undeclared", "value"),
        ] {
            let mut values = HashMap::from([(key.to_string(), value.to_string())]);
            let error = resolve_noninteractive_required_config(&config, &mut values)
                .expect_err("invalid inline configuration must fail");
            assert!(error.to_string().contains(key), "unexpected error: {error}");
        }
    }

    #[test]
    fn noninteractive_config_applies_defaults_to_optional_fields() {
        let config = json!({
            "configSchema": {
                "variant": {"type": "select", "options": ["a", "b"], "default": "a"},
                "features": {"type": "select", "multiSelect": true, "options": ["x", "y"], "default": "y"}
            }
        });
        let mut values = HashMap::new();

        resolve_noninteractive_required_config(&config, &mut values).unwrap();

        assert_eq!(values.get("variant").map(String::as_str), Some("a"));
        assert_eq!(values.get("features").map(String::as_str), Some("y"));
    }

    #[test]
    fn config_source_parent_reference_cannot_select_file_outside_extraction() {
        let outer = tempfile::tempdir().unwrap();
        let extract = outer.path().join("package");
        std::fs::create_dir(&extract).unwrap();
        std::fs::write(outer.path().join("secret.txt"), "secret").unwrap();

        let error = filter_config_files(
            &extract,
            &[json!({"src": "../secret.txt", "dest": "copied.txt"})],
            &HashMap::new(),
        )
        .expect_err("parent source selector must be rejected");

        assert!(
            error.to_string().contains("parent"),
            "unexpected source-selector error: {error}"
        );
    }

    #[test]
    fn nested_legacy_source_directory_keeps_extraction_relative_source_paths() {
        let extract = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(extract.path().join("src/components")).unwrap();
        std::fs::write(
            extract.path().join("package.json"),
            r#"{"lpm":{"source":"src/components"}}"#,
        )
        .unwrap();
        std::fs::write(extract.path().join("src/components/Button.tsx"), "button").unwrap();

        assert_eq!(
            collect_source_with_fallback(extract.path()).unwrap(),
            vec![("src/components/Button.tsx".into(), "Button.tsx".into())]
        );
    }

    #[test]
    fn nested_legacy_source_file_keeps_extraction_relative_source_path() {
        let extract = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(extract.path().join("src/components")).unwrap();
        std::fs::write(
            extract.path().join("package.json"),
            r#"{"lpm":{"source":"src/components/Button.tsx"}}"#,
        )
        .unwrap();
        std::fs::write(extract.path().join("src/components/Button.tsx"), "button").unwrap();

        assert_eq!(
            collect_source_with_fallback(extract.path()).unwrap(),
            vec![("src/components/Button.tsx".into(), "Button.tsx".into())]
        );
    }

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
            let out =
                filter_config_files(dir.path(), &rules, &config(&[("withTests", "true")])).unwrap();
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
            let out = filter_config_files(dir.path(), &rules, &config(&[("withTests", "false")]))
                .unwrap();
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
            let out =
                filter_config_files(dir.path(), &rules, &config(&[("withTests", "true")])).unwrap();
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
            let out = filter_config_files(dir.path(), &rules, &HashMap::new()).unwrap();
            assert_eq!(
                out.len(),
                1,
                "missing param must include the file (all-by-default): {out:?}",
            );
        }
    }
}
