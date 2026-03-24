//! Package.swift editing for SE-0292 registry dependencies.
//!
//! Provides functions to:
//! - Convert LPM package names to SE-0292 identifiers
//! - Find and parse Package.swift manifests
//! - Insert registry dependencies into Package.swift
//! - Run `swift package resolve`

use lpm_common::{LpmError, PackageName};
use std::path::{Path, PathBuf};

/// Convert an LPM package name to an SE-0292 registry identifier.
///
/// `@lpm.dev/owner.pkg-name` → `lpmdev.owner-pkg-name`
pub fn lpm_to_se0292_id(name: &PackageName) -> String {
    format!("lpmdev.{}-{}", name.owner, name.name)
}

/// Walk up from `dir` to find a Package.swift file.
pub fn find_package_swift(dir: &Path) -> Option<PathBuf> {
    let mut current = dir.to_path_buf();
    loop {
        let manifest = current.join("Package.swift");
        if manifest.exists() {
            return Some(manifest);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Get non-test target names from the current SPM package.
/// Runs `swift package dump-package` and parses the JSON output.
pub fn get_spm_targets(project_dir: &Path) -> Result<Vec<String>, LpmError> {
    let output = std::process::Command::new("swift")
        .args(["package", "dump-package"])
        .current_dir(project_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| LpmError::Registry(format!("failed to run swift: {e}")))?;

    if !output.status.success() {
        return Err(LpmError::Registry(
            "swift package dump-package failed".into(),
        ));
    }

    let manifest: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| LpmError::Registry(format!("failed to parse manifest: {e}")))?;

    let targets = manifest
        .get("targets")
        .and_then(|t| t.as_array())
        .map(|targets| {
            targets
                .iter()
                .filter(|t| t.get("type").and_then(|v| v.as_str()) != Some("test"))
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(targets)
}

/// Result of editing a Package.swift manifest.
pub struct ManifestEdit {
    pub already_exists: bool,
    pub dependency_added: bool,
    pub product_added_to_target: Option<String>,
}

/// Add an SE-0292 registry dependency to Package.swift.
///
/// Inserts:
/// 1. `.package(id: "lpmdev.owner-pkg", from: "1.0.0")` into top-level dependencies
/// 2. `.product(name: "ProductName", package: "lpmdev.owner-pkg")` into target dependencies
///
/// Idempotent — skips if the dependency already exists.
pub fn add_registry_dependency(
    manifest_path: &Path,
    se0292_id: &str,
    version: &str,
    product_name: &str,
    target_name: &str,
) -> Result<ManifestEdit, LpmError> {
    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| LpmError::Registry(format!("failed to read Package.swift: {e}")))?;

    // Check if dependency already exists
    if content.contains(&format!("\"{}\"", se0292_id)) {
        return Ok(ManifestEdit {
            already_exists: true,
            dependency_added: false,
            product_added_to_target: None,
        });
    }

    let dep_entry = format!(".package(id: \"{}\", from: \"{}\")", se0292_id, version);
    let product_entry = format!(
        ".product(name: \"{}\", package: \"{}\")",
        product_name, se0292_id
    );

    // Step 1: Insert package dependency into top-level dependencies array.
    // Find the first `dependencies: [` that appears BEFORE the `targets:` keyword.
    let content = insert_into_dependencies_array(&content, &dep_entry, None)?;

    // Step 2: Insert product into the target's dependencies array.
    let content = insert_into_target_deps(&content, target_name, &product_entry)?;

    std::fs::write(manifest_path, &content)
        .map_err(|e| LpmError::Registry(format!("failed to write Package.swift: {e}")))?;

    Ok(ManifestEdit {
        already_exists: false,
        dependency_added: true,
        product_added_to_target: Some(target_name.to_string()),
    })
}

/// Insert an entry into the top-level `dependencies: [...]` array.
/// If `before_keyword` is Some, only consider arrays that appear before that keyword.
fn insert_into_dependencies_array(
    content: &str,
    entry: &str,
    before_keyword: Option<&str>,
) -> Result<String, LpmError> {
    let search_limit = before_keyword
        .and_then(|kw| content.find(kw))
        .unwrap_or(content.len());

    // Find `dependencies: [` before the limit
    let deps_start = content[..search_limit]
        .find("dependencies:")
        .ok_or_else(|| {
            LpmError::Registry("Could not find 'dependencies:' in Package.swift".into())
        })?;

    // Find the opening bracket
    let bracket_start = content[deps_start..]
        .find('[')
        .map(|i| deps_start + i)
        .ok_or_else(|| LpmError::Registry("Malformed dependencies block".into()))?;

    // Find the matching closing bracket
    let close_pos = find_matching_bracket(content, bracket_start).ok_or_else(|| {
        LpmError::Registry("Could not find closing bracket for dependencies".into())
    })?;

    // Detect indentation from existing entries or use 8 spaces
    let indent = detect_indent(content, bracket_start, close_pos);

    // Check if array is empty (only whitespace between brackets)
    let inner = content[bracket_start + 1..close_pos].trim();
    if inner.is_empty() {
        // Empty array: expand to multiline
        let new_content = format!(
            "{}\n{}{},\n{}{}",
            &content[..bracket_start + 1],
            indent,
            entry,
            &indent[..indent.len().saturating_sub(4)], // closing bracket indent
            &content[close_pos..]
        );
        return Ok(new_content);
    }

    // Non-empty: insert before the closing bracket
    // Find the last non-whitespace character before the closing bracket
    let before_close = content[bracket_start + 1..close_pos].trim_end();
    let needs_comma = !before_close.ends_with(',');

    let insert_pos = close_pos;
    let mut new_content = String::with_capacity(content.len() + entry.len() + 20);
    new_content.push_str(&content[..insert_pos]);

    // Add comma to previous entry if needed
    if needs_comma {
        // Find the last non-whitespace position before close_pos
        let last_char_pos = content[..close_pos]
            .rfind(|c: char| !c.is_whitespace())
            .unwrap_or(close_pos - 1);
        new_content.clear();
        new_content.push_str(&content[..last_char_pos + 1]);
        new_content.push(',');
        new_content.push('\n');
        new_content.push_str(&indent);
        new_content.push_str(entry);
        new_content.push(',');
        new_content.push('\n');
        // Preserve the whitespace before the closing bracket
        let close_line_indent = get_line_indent(content, close_pos);
        new_content.push_str(&close_line_indent);
        new_content.push_str(&content[close_pos..]);
    } else {
        new_content.push_str(&indent);
        new_content.push_str(entry);
        new_content.push(',');
        new_content.push('\n');
        // Preserve the whitespace before the closing bracket
        let close_line_indent = get_line_indent(content, close_pos);
        new_content.push_str(&close_line_indent);
        new_content.push_str(&content[close_pos..]);
    }

    Ok(new_content)
}

/// Insert a product entry into a specific target's `dependencies: [...]` array.
fn insert_into_target_deps(
    content: &str,
    target_name: &str,
    entry: &str,
) -> Result<String, LpmError> {
    // Find the target declaration — must be inside the targets array, not the Package name.
    // Search for patterns like `.target(name: "X"`, `.executableTarget(name: "X"`, etc.
    let target_pattern = format!("name: \"{}\"", target_name);
    let targets_section = content.find("targets:").ok_or_else(|| {
        LpmError::Registry("Could not find 'targets:' in Package.swift".into())
    })?;

    // Search for the target name AFTER the targets: keyword
    let target_pos = content[targets_section..]
        .find(&target_pattern)
        .map(|i| targets_section + i)
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "Could not find target '{}' in Package.swift",
                target_name
            ))
        })?;

    // Find `dependencies: [` after the target declaration
    let deps_search = &content[target_pos..];
    let deps_offset = deps_search.find("dependencies:").ok_or_else(|| {
        LpmError::Registry(format!(
            "Target '{}' has no dependencies array. Add one manually.",
            target_name
        ))
    })?;
    let deps_start = target_pos + deps_offset;

    // Find the opening bracket
    let bracket_start = content[deps_start..]
        .find('[')
        .map(|i| deps_start + i)
        .ok_or_else(|| LpmError::Registry("Malformed target dependencies block".into()))?;

    // Find the matching closing bracket
    let close_pos = find_matching_bracket(content, bracket_start).ok_or_else(|| {
        LpmError::Registry("Could not find closing bracket for target dependencies".into())
    })?;

    let indent = detect_indent(content, bracket_start, close_pos);
    let inner = content[bracket_start + 1..close_pos].trim();

    if inner.is_empty() {
        // Empty array
        let close_indent = &indent[..indent.len().saturating_sub(4)];
        let new_content = format!(
            "{}\n{}{},\n{}{}",
            &content[..bracket_start + 1],
            indent,
            entry,
            close_indent,
            &content[close_pos..]
        );
        return Ok(new_content);
    }

    // Non-empty: insert before closing bracket
    let before_close = content[bracket_start + 1..close_pos].trim_end();
    let needs_comma = !before_close.ends_with(',');

    let mut new_content = String::with_capacity(content.len() + entry.len() + 20);

    if needs_comma {
        let last_char_pos = content[..close_pos]
            .rfind(|c: char| !c.is_whitespace())
            .unwrap_or(close_pos - 1);
        new_content.push_str(&content[..last_char_pos + 1]);
        new_content.push(',');
        new_content.push('\n');
        new_content.push_str(&indent);
        new_content.push_str(entry);
        new_content.push(',');
        new_content.push('\n');
        let close_line_indent = get_line_indent(content, close_pos);
        new_content.push_str(&close_line_indent);
        new_content.push_str(&content[close_pos..]);
    } else {
        new_content.push_str(&content[..close_pos]);
        new_content.push_str(&indent);
        new_content.push_str(entry);
        new_content.push(',');
        new_content.push('\n');
        let close_line_indent = get_line_indent(content, close_pos);
        new_content.push_str(&close_line_indent);
        new_content.push_str(&content[close_pos..]);
    }

    Ok(new_content)
}

/// Find the position of the closing bracket `]` matching the opening bracket at `open_pos`.
fn find_matching_bracket(content: &str, open_pos: usize) -> Option<usize> {
    let mut depth = 0;
    let mut in_string = false;

    for (i, ch) in content[open_pos..].char_indices() {
        match ch {
            '"' if !in_string => in_string = true,
            '"' if in_string => in_string = false,
            '[' if !in_string => depth += 1,
            ']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(open_pos + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Detect indentation of entries inside a bracket pair.
fn detect_indent(content: &str, bracket_start: usize, bracket_end: usize) -> String {
    let inner = &content[bracket_start + 1..bracket_end];
    // Find first non-empty line to detect indent
    for line in inner.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && trimmed.starts_with('.') {
            let indent_len = line.len() - line.trim_start().len();
            return " ".repeat(indent_len);
        }
    }
    // Default: 8 spaces (standard Swift indentation for nested arrays)
    "        ".to_string()
}

/// Get the leading whitespace of the line containing the given position.
fn get_line_indent(content: &str, pos: usize) -> String {
    let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line = &content[line_start..pos];
    let indent_len = line.len() - line.trim_start().len();
    " ".repeat(indent_len)
}

/// Run `swift package resolve` in the given directory.
pub fn run_swift_resolve(project_dir: &Path) -> Result<(), LpmError> {
    let status = std::process::Command::new("swift")
        .args(["package", "resolve"])
        .current_dir(project_dir)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| LpmError::Registry(format!("failed to run swift package resolve: {e}")))?;

    if !status.success() {
        return Err(LpmError::Registry(
            "swift package resolve failed. Run `lpm swift-registry` to configure SPM first."
                .into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lpm_to_se0292_id() {
        let name = PackageName::parse("@lpm.dev/acme.swift-logger").unwrap();
        assert_eq!(lpm_to_se0292_id(&name), "lpmdev.acme-swift-logger");

        let name2 = PackageName::parse("@lpm.dev/neo.haptic").unwrap();
        assert_eq!(lpm_to_se0292_id(&name2), "lpmdev.neo-haptic");
    }

    #[test]
    fn test_add_dependency_to_existing() {
        let input = r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    platforms: [.macOS(.v12)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.60.0"),
    ],
    targets: [
        .target(name: "MyApp", dependencies: [
            .product(name: "NIOCore", package: "swift-nio"),
        ]),
    ]
)
"#;

        let result = add_registry_dependency(
            Path::new("/tmp/test-manifest.swift"),
            "lpmdev.acme-swift-logger",
            "1.0.0",
            "Logger",
            "MyApp",
        );

        // Can't test file I/O in unit test, so test the internal functions
        let content = insert_into_dependencies_array(
            input,
            ".package(id: \"lpmdev.acme-swift-logger\", from: \"1.0.0\")",
            Some("targets:"),
        )
        .unwrap();

        assert!(content.contains("lpmdev.acme-swift-logger"));
        assert!(content.contains(".package(url:")); // existing dep preserved

        let content = insert_into_target_deps(
            &content,
            "MyApp",
            ".product(name: \"Logger\", package: \"lpmdev.acme-swift-logger\")",
        )
        .unwrap();

        assert!(content.contains("product(name: \"Logger\""));
        assert!(content.contains("product(name: \"NIOCore\"")); // existing preserved
    }

    #[test]
    fn test_add_dependency_to_empty() {
        let input = r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [],
    targets: [
        .target(name: "MyApp", dependencies: []),
    ]
)
"#;

        let content = insert_into_dependencies_array(
            input,
            ".package(id: \"lpmdev.acme-logger\", from: \"1.0.0\")",
            Some("targets:"),
        )
        .unwrap();

        assert!(content.contains("lpmdev.acme-logger"));

        let content = insert_into_target_deps(
            &content,
            "MyApp",
            ".product(name: \"Logger\", package: \"lpmdev.acme-logger\")",
        )
        .unwrap();

        assert!(content.contains("product(name: \"Logger\""));
    }

    #[test]
    fn test_find_matching_bracket() {
        let content = "dependencies: [\n    .package(url: \"test\"),\n]";
        let open = content.find('[').unwrap();
        let close = find_matching_bracket(content, open).unwrap();
        assert_eq!(&content[close..close + 1], "]");
    }
}
