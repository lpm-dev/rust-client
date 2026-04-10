#![allow(dead_code)]

//! Assertion helpers for verifying CLI workflow outputs.
//!
//! These helpers inspect the artifacts that `lpm-rs` produces: lockfiles,
//! store directories, node_modules layouts, and JSON output structure.

use std::path::Path;

/// Assert that lpm.lock exists and contains the expected package.
pub fn assert_lockfile_contains(project_dir: &Path, package_name: &str) {
    let lockfile_path = project_dir.join("lpm.lock");
    assert!(
        lockfile_path.exists(),
        "lpm.lock not found at {}",
        lockfile_path.display()
    );

    let content = std::fs::read_to_string(&lockfile_path).expect("failed to read lpm.lock");
    assert!(
        content.contains(package_name),
        "lpm.lock does not contain package '{package_name}'.\nContents:\n{content}"
    );
}

/// Assert that lpm.lock exists.
pub fn assert_lockfile_exists(project_dir: &Path) {
    let lockfile_path = project_dir.join("lpm.lock");
    assert!(
        lockfile_path.exists(),
        "lpm.lock not found at {}",
        lockfile_path.display()
    );
}

/// Assert that lpm.lockb (binary lockfile) exists.
pub fn assert_binary_lockfile_exists(project_dir: &Path) {
    let lockb_path = project_dir.join("lpm.lockb");
    assert!(
        lockb_path.exists(),
        "lpm.lockb not found at {}",
        lockb_path.display()
    );
}

/// Assert that both lpm.lock and lpm.lockb exist.
pub fn assert_both_lockfiles_exist(project_dir: &Path) {
    assert_lockfile_exists(project_dir);
    assert_binary_lockfile_exists(project_dir);
}

/// Assert that a backup file exists (used by migrate).
pub fn assert_backup_exists(project_dir: &Path, original_name: &str) {
    let backup_path = project_dir.join(format!("{original_name}.backup"));
    assert!(
        backup_path.exists(),
        "backup file not found: {}.backup",
        original_name
    );
}

/// Assert that node_modules directory exists.
pub fn assert_node_modules_exists(project_dir: &Path) {
    let nm = project_dir.join("node_modules");
    assert!(nm.exists(), "node_modules not found");
}

/// Assert that a specific package is linked in node_modules.
pub fn assert_in_node_modules(project_dir: &Path, package_name: &str) {
    let pkg_dir = project_dir.join("node_modules").join(package_name);
    assert!(
        pkg_dir.exists(),
        "package '{package_name}' not found in node_modules"
    );

    let pkg_json = pkg_dir.join("package.json");
    assert!(
        pkg_json.exists(),
        "package.json not found for '{package_name}' in node_modules"
    );
}

/// Parse JSON output from stdout and return it as a Value.
///
/// The CLI may emit tracing/warning lines before the JSON object.
/// This function finds the first `{` and parses from there.
///
/// Panics with a helpful message if no valid JSON is found.
pub fn parse_json_output(stdout: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout);

    // Try parsing the whole thing first (fast path)
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
        return val;
    }

    // Find the first '{' and try parsing from there (handles WARN/DEBUG prefix lines)
    if let Some(start) = text.find('{')
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&text[start..])
    {
        return val;
    }

    panic!("stdout does not contain valid JSON:\n{text}");
}

/// Assert that a JSON value has a field with the expected type.
pub fn assert_json_field(json: &serde_json::Value, field: &str, expected_type: JsonType) {
    let value = &json[field];
    assert!(
        !value.is_null(),
        "missing JSON field '{field}' in: {}",
        serde_json::to_string_pretty(json).unwrap()
    );

    let matches = match expected_type {
        JsonType::Bool => value.is_boolean(),
        JsonType::Number => value.is_number(),
        JsonType::String => value.is_string(),
        JsonType::Array => value.is_array(),
        JsonType::Object => value.is_object(),
    };

    assert!(
        matches,
        "JSON field '{field}' expected {expected_type:?} but got: {value}"
    );
}

/// Expected JSON value type for assertions.
#[derive(Debug)]
pub enum JsonType {
    Bool,
    Number,
    String,
    Array,
    Object,
}
