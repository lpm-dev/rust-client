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
    // Finding #16: pipe stderr so diagnostics are available in error messages
    let output = std::process::Command::new("swift")
        .args(["package", "dump-package"])
        .current_dir(project_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| LpmError::Registry(format!("failed to run swift: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LpmError::Registry(format!(
            "swift package dump-package failed: {}",
            stderr.trim()
        )));
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
}

/// Validate that a string value is safe to interpolate into Package.swift.
/// Rejects characters that could break out of a Swift string literal or inject code.
fn validate_manifest_value(value: &str, label: &str) -> Result<(), LpmError> {
    const DANGEROUS: &[char] = &['"', ')', '(', '\n', '\r', '\\'];
    if let Some(bad) = value.chars().find(|c| DANGEROUS.contains(c)) {
        return Err(LpmError::Registry(format!(
            "Invalid {label}: contains disallowed character {bad:?}"
        )));
    }
    Ok(())
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
    // Finding #6: validate inputs before interpolation
    validate_manifest_value(version, "version")?;
    validate_manifest_value(product_name, "product_name")?;

    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| LpmError::Registry(format!("failed to read Package.swift: {e}")))?;

    // Check if dependency already exists
    if content.contains(&format!("\"{}\"", se0292_id)) {
        return Ok(ManifestEdit {
            already_exists: true,
        });
    }

    let dep_entry = format!(".package(id: \"{}\", from: \"{}\")", se0292_id, version);
    let product_entry = format!(
        ".product(name: \"{}\", package: \"{}\")",
        product_name, se0292_id
    );

    // Step 1: Insert package dependency into top-level dependencies array.
    // Finding #1: pass Some("targets:") so we only find the top-level dependencies array,
    // not a target-level dependencies array.
    let content = insert_into_dependencies_array(&content, &dep_entry, Some("targets:"))?;

    // Step 2: Insert product into the target's dependencies array.
    let content = insert_into_target_deps(&content, target_name, &product_entry)?;

    std::fs::write(manifest_path, &content)
        .map_err(|e| LpmError::Registry(format!("failed to write Package.swift: {e}")))?;

    Ok(ManifestEdit {
        already_exists: false,
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
    let deps_start = match content[..search_limit].find("dependencies:") {
        Some(pos) => pos,
        None => {
            // No top-level `dependencies:` array exists — insert one before the keyword.
            // This handles Swift 6.3+ manifests where `swift package init` omits the array.
            if let Some(kw) = before_keyword
                && let Some(kw_pos) = content.find(kw)
            {
                let kw_indent = get_line_indent(content, kw_pos);
                let entry_indent = indent_one_level(&kw_indent);
                let new_deps = format!(
                    "{}dependencies: [\n{}{},\n{}],\n",
                    kw_indent, entry_indent, entry, kw_indent
                );
                // Insert the new dependencies array on a new line before the keyword line.
                // content[line_start..] already includes the keyword's own indentation,
                // so we don't append kw_indent again.
                let line_start = content[..kw_pos]
                    .rfind('\n')
                    .map(|i| i + 1)
                    .unwrap_or(kw_pos);
                let mut new_content = String::with_capacity(content.len() + new_deps.len() + 10);
                new_content.push_str(&content[..line_start]);
                new_content.push_str(&new_deps);
                new_content.push_str(&content[line_start..]);
                return Ok(new_content);
            }
            return Err(LpmError::Registry(
                "Could not find 'dependencies:' in Package.swift".into(),
            ));
        }
    };

    // Find the opening bracket
    let bracket_start = content[deps_start..]
        .find('[')
        .map(|i| deps_start + i)
        .ok_or_else(|| LpmError::Registry("Malformed dependencies block".into()))?;

    // Find the matching closing bracket
    let close_pos = find_matching_bracket(content, bracket_start).ok_or_else(|| {
        LpmError::Registry("Could not find closing bracket for dependencies".into())
    })?;

    // Detect indentation from existing entries or derive from context
    let indent = detect_indent(content, bracket_start, close_pos);

    // Check if array is empty (only whitespace between brackets)
    let inner = content[bracket_start + 1..close_pos].trim();
    if inner.is_empty() {
        // Finding #11: derive closing bracket indent from the opening bracket's line
        let close_indent = get_line_indent(content, bracket_start);
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

    // Non-empty: insert a new entry before the closing bracket line.
    // The closing `]` sits on its own line with leading whitespace. We insert
    // the new entry on a new line just before that line, using the detected indent.
    let before_close = content[bracket_start + 1..close_pos].trim_end();
    let needs_comma = !before_close.ends_with(',');

    // Find the start of the line containing `]` — we'll insert before it
    let close_line_start = content[..close_pos]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(close_pos);

    let mut new_content = String::with_capacity(content.len() + entry.len() + 20);

    if needs_comma {
        // Find the last non-whitespace position before close_pos and add comma
        let last_char_pos = content[..close_pos]
            .rfind(|c: char| !c.is_whitespace())
            .unwrap_or(close_pos - 1);
        new_content.push_str(&content[..last_char_pos + 1]);
        new_content.push(',');
        new_content.push('\n');
    } else {
        // Content up to the close line (everything before the `]` line)
        new_content.push_str(&content[..close_line_start]);
    }

    new_content.push_str(&indent);
    new_content.push_str(entry);
    new_content.push(',');
    new_content.push('\n');
    // Keep the original `]` line (with its whitespace) intact
    new_content.push_str(&content[close_line_start..]);

    Ok(new_content)
}

/// Insert a product entry into a specific target's `dependencies: [...]` array.
fn insert_into_target_deps(
    content: &str,
    target_name: &str,
    entry: &str,
) -> Result<String, LpmError> {
    // Find the target declaration -- must be inside the targets array, not the Package name.
    let target_pattern = format!("name: \"{}\"", target_name);
    let targets_section = content
        .find("targets:")
        .ok_or_else(|| LpmError::Registry("Could not find 'targets:' in Package.swift".into()))?;

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

    // Finding #4: find the enclosing target call boundary using paren matching.
    // Walk backwards from target_pos to find the opening `(` of `.target(` or `.executableTarget(`.
    let target_call_open = content[..target_pos].rfind('(').ok_or_else(|| {
        LpmError::Registry(format!(
            "Could not find opening '(' for target '{}'",
            target_name
        ))
    })?;

    // Find the matching closing `)` to bound our search for `dependencies:`.
    let target_call_close = find_matching_paren(content, target_call_open).ok_or_else(|| {
        LpmError::Registry(format!(
            "Could not find closing ')' for target '{}'",
            target_name
        ))
    })?;

    // Search for `dependencies:` only within this target's scope
    let target_scope = &content[target_pos..target_call_close];
    let deps_offset = target_scope.find("dependencies:");

    let (bracket_start, close_pos) = if let Some(offset) = deps_offset {
        let deps_start = target_pos + offset;
        let bs = content[deps_start..]
            .find('[')
            .map(|i| deps_start + i)
            .ok_or_else(|| LpmError::Registry("Malformed target dependencies block".into()))?;
        let cp = find_matching_bracket(content, bs).ok_or_else(|| {
            LpmError::Registry("Could not find closing bracket for target dependencies".into())
        })?;
        (bs, cp)
    } else {
        // Target has no dependencies array -- insert one.
        let name_end = target_pos + target_pattern.len();
        // Find the next comma or end of arguments after the name
        let after_name = &content[name_end..target_call_close];
        let (insert_after, needs_leading_comma) = if let Some(comma_pos) = after_name.find(',') {
            (name_end + comma_pos + 1, false)
        } else {
            // No comma after the name — we need to add one as separator
            (name_end, true)
        };

        // Detect the indent for the target's arguments.
        // `target_indent` is the indent of the `name:` line (same level as `dependencies:`).
        // Entry indent is one unit deeper — detect the unit from surrounding context.
        let target_indent = get_line_indent(content, target_pos);
        let entry_indent = indent_one_level_from_context(content, &target_indent);
        let leading_comma = if needs_leading_comma { "," } else { "" };
        let new_deps = format!(
            "{}\n{}dependencies: [\n{}{},\n{}]",
            leading_comma, target_indent, entry_indent, entry, target_indent
        );

        // Check if we need a trailing comma for subsequent arguments
        let rest_trimmed = content[insert_after..target_call_close].trim();
        let needs_trailing_comma = !rest_trimmed.is_empty();

        let mut new_content = String::with_capacity(content.len() + new_deps.len() + 10);
        new_content.push_str(&content[..insert_after]);
        new_content.push_str(&new_deps);
        if needs_trailing_comma {
            new_content.push(',');
        }
        new_content.push_str(&content[insert_after..]);
        return Ok(new_content);
    };

    let indent = detect_indent(content, bracket_start, close_pos);
    let inner = content[bracket_start + 1..close_pos].trim();

    if inner.is_empty() {
        // Finding #11: derive closing bracket indent from context
        let close_indent = get_line_indent(content, bracket_start);
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

    // Non-empty: insert new entry before the closing bracket line.
    let before_close = content[bracket_start + 1..close_pos].trim_end();
    let needs_comma = !before_close.ends_with(',');

    let close_line_start = content[..close_pos]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(close_pos);

    let mut new_content = String::with_capacity(content.len() + entry.len() + 20);

    if needs_comma {
        let last_char_pos = content[..close_pos]
            .rfind(|c: char| !c.is_whitespace())
            .unwrap_or(close_pos - 1);
        new_content.push_str(&content[..last_char_pos + 1]);
        new_content.push(',');
        new_content.push('\n');
    } else {
        new_content.push_str(&content[..close_line_start]);
    }

    new_content.push_str(&indent);
    new_content.push_str(entry);
    new_content.push(',');
    new_content.push('\n');
    new_content.push_str(&content[close_line_start..]);

    Ok(new_content)
}

/// Find the position of the closing bracket `]` matching the opening bracket at `open_pos`.
/// Handles escaped quotes, line comments (`//`), and block comments (`/* */`).
fn find_matching_bracket(content: &str, open_pos: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut depth = 0i32;
    let mut i = open_pos;

    while i < len {
        let b = bytes[i];
        match b {
            b'"' => {
                // Enter string -- scan until unescaped closing quote
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' {
                        i += 2; // skip escaped character
                        continue;
                    }
                    if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
                // i now points at the closing quote (or past end)
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'/' => {
                // Line comment -- skip to end of line
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                continue; // don't increment i again
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                // Block comment -- skip to */
                i += 2;
                while i + 1 < len {
                    if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        i += 1; // will be incremented past '/' below
                        break;
                    }
                    i += 1;
                }
            }
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Find the position of the closing paren `)` matching the opening paren at `open_pos`.
/// Handles strings, line comments, and block comments.
fn find_matching_paren(content: &str, open_pos: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut depth = 0i32;
    let mut i = open_pos;

    while i < len {
        let b = bytes[i];
        match b {
            b'"' => {
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'/' => {
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < len {
                    if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Detect indentation of entries inside a bracket pair.
/// Returns the actual whitespace characters (tabs or spaces) used for indentation.
fn detect_indent(content: &str, bracket_start: usize, bracket_end: usize) -> String {
    let inner = &content[bracket_start + 1..bracket_end];
    // Find first non-empty line to detect indent, preserving actual whitespace chars
    for line in inner.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && trimmed.starts_with('.') {
            let leading = &line[..line.len() - line.trim_start().len()];
            return leading.to_string();
        }
    }
    // No existing entries: derive from the bracket's line indent + one indent level
    let bracket_indent = get_line_indent(content, bracket_start);
    indent_one_level(&bracket_indent)
}

/// Add one level of indentation to the given indent string.
/// Detects whether the indent uses tabs or spaces, and adds one unit.
fn indent_one_level(base_indent: &str) -> String {
    if base_indent.contains('\t') {
        format!("{}\t", base_indent)
    } else {
        // Detect indent unit from the base: if base is e.g. 2 spaces, unit is 2.
        // If base is empty, default to 4 spaces.
        let unit = if base_indent.is_empty() {
            4
        } else {
            base_indent.len()
        };
        format!("{}{}", base_indent, " ".repeat(unit))
    }
}

/// Add one level of indentation, detecting the indent unit from the file content.
/// Unlike `indent_one_level`, this scans the file for the minimum non-zero indent
/// to determine the actual indent width (e.g., 4 spaces even when base is 12 spaces deep).
fn indent_one_level_from_context(content: &str, base_indent: &str) -> String {
    if base_indent.contains('\t') {
        return format!("{}\t", base_indent);
    }

    // Scan lines to find the minimum non-zero space indent — that's one indent unit
    let mut min_indent = usize::MAX;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        let leading = line.len() - trimmed.len();
        if leading > 0 && leading < min_indent {
            min_indent = leading;
        }
    }

    let unit = if min_indent == usize::MAX {
        4
    } else {
        min_indent
    };
    format!("{}{}", base_indent, " ".repeat(unit))
}

/// Get the leading whitespace of the line containing the given position.
/// Preserves actual whitespace characters (tabs or spaces).
fn get_line_indent(content: &str, pos: usize) -> String {
    let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line = &content[line_start..pos];
    let leading = &line[..line.len() - line.trim_start().len()];
    leading.to_string()
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
            "swift package resolve failed. Run `lpm swift-registry` to configure SPM first.".into(),
        ));
    }

    Ok(())
}

// ── Xcode Wrapper Package (Packages/LPMDependencies/) ──────────────────

/// Directory name for the LPM dependencies wrapper package.
pub const LPM_DEPS_PACKAGE_NAME: &str = "LPMDependencies";

/// Relative path from the project root to the wrapper package.
pub const LPM_DEPS_REL_PATH: &str = "Packages/LPMDependencies";

/// Result of ensuring the wrapper package exists.
pub struct WrapperPackageResult {
    pub created: bool,
    pub manifest_path: PathBuf,
}

/// Ensure the LPMDependencies wrapper package exists under `project_dir/Packages/LPMDependencies/`.
///
/// If it doesn't exist yet, scaffolds the directory structure with Package.swift and Exports.swift.
/// If it already exists, returns the existing manifest path.
pub fn ensure_wrapper_package(project_dir: &Path) -> Result<WrapperPackageResult, LpmError> {
    let pkg_dir = project_dir.join(LPM_DEPS_REL_PATH);
    let manifest_path = pkg_dir.join("Package.swift");

    if manifest_path.exists() {
        return Ok(WrapperPackageResult {
            created: false,
            manifest_path,
        });
    }

    // Create directory structure
    let sources_dir = pkg_dir.join("Sources").join(LPM_DEPS_PACKAGE_NAME);
    std::fs::create_dir_all(&sources_dir)
        .map_err(|e| LpmError::Registry(format!("failed to create {}: {e}", pkg_dir.display())))?;

    // Write Package.swift
    // Note: the template uses multi-line arrays and avoids `targets:` inside product
    // declarations (like `targets: ["X"]`) to prevent `insert_into_dependencies_array`
    // from confusing inline `targets:` with the top-level `targets:` keyword.
    let manifest = r#"// swift-tools-version: 5.9
// Managed by lpm — do not edit manually.

import PackageDescription

let package = Package(
    name: "LPMDependencies",
    platforms: [.iOS(.v13), .macOS(.v10_15)],
    products: [
        .library(
            name: "LPMDependencies",
            targets: ["LPMDependencies"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "LPMDependencies",
            dependencies: []
        ),
    ]
)
"#;
    std::fs::write(&manifest_path, manifest)
        .map_err(|e| LpmError::Registry(format!("failed to write Package.swift: {e}")))?;

    // Write Exports.swift — re-exports are added by add_wrapper_dependency()
    let exports = "// Managed by lpm — do not edit manually.\n\
                   // Re-exports all LPM dependencies so they are importable from any target.\n";
    std::fs::write(sources_dir.join("Exports.swift"), exports)
        .map_err(|e| LpmError::Registry(format!("failed to write Exports.swift: {e}")))?;

    Ok(WrapperPackageResult {
        created: true,
        manifest_path,
    })
}

/// Add an SE-0292 registry dependency to the LPMDependencies wrapper Package.swift.
///
/// Uses `None` as the `before_keyword` for the top-level dependencies array because
/// the wrapper template has inline `targets:` inside `.library(targets: [...])` which
/// would confuse the `Some("targets:")` search. Since the wrapper Package.swift is
/// generated by us, the first `dependencies:` array IS the top-level one.
pub fn add_wrapper_dependency(
    manifest_path: &Path,
    se0292_id: &str,
    version: &str,
    product_name: &str,
) -> Result<ManifestEdit, LpmError> {
    validate_manifest_value(version, "version")?;
    validate_manifest_value(product_name, "product_name")?;

    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| LpmError::Registry(format!("failed to read Package.swift: {e}")))?;

    // Check if dependency already exists
    if content.contains(&format!("\"{}\"", se0292_id)) {
        return Ok(ManifestEdit {
            already_exists: true,
        });
    }

    let dep_entry = format!(".package(id: \"{}\", from: \"{}\")", se0292_id, version);
    let product_entry = format!(
        ".product(name: \"{}\", package: \"{}\")",
        product_name, se0292_id
    );

    // Insert into top-level dependencies — use None as before_keyword since we
    // control the template and the first `dependencies:` IS the top-level one.
    let content = insert_into_dependencies_array(&content, &dep_entry, None)?;

    // Insert product into the LPMDependencies target's dependencies array
    let content = insert_into_target_deps(&content, LPM_DEPS_PACKAGE_NAME, &product_entry)?;

    std::fs::write(manifest_path, &content)
        .map_err(|e| LpmError::Registry(format!("failed to write Package.swift: {e}")))?;

    // Add @_exported import to Exports.swift so the module is importable from
    // any target that links LPMDependencies (explicit re-export, not relying on
    // Xcode build system behavior).
    let exports_path = manifest_path
        .parent()
        .unwrap()
        .join("Sources")
        .join(LPM_DEPS_PACKAGE_NAME)
        .join("Exports.swift");
    if exports_path.exists() {
        let exports_content = std::fs::read_to_string(&exports_path)
            .map_err(|e| LpmError::Registry(format!("failed to read Exports.swift: {e}")))?;
        let import_line = format!("@_exported import {}", product_name);
        if !exports_content.contains(&import_line) {
            let updated = format!("{}{}\n", exports_content, import_line);
            std::fs::write(&exports_path, updated)
                .map_err(|e| LpmError::Registry(format!("failed to write Exports.swift: {e}")))?;
        }
    }

    Ok(ManifestEdit {
        already_exists: false,
    })
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

        let _result = add_registry_dependency(
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

    // === Finding #1: before_keyword — inserts dependencies array when missing ===
    #[test]
    fn test_finding1_inserts_dependencies_when_missing_before_targets() {
        // Package.swift where there's NO top-level `dependencies:` before `targets:`,
        // but a target has `dependencies:`.
        let input = r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    targets: [
        .target(name: "MyApp", dependencies: [
            .product(name: "NIOCore", package: "swift-nio"),
        ]),
    ]
)
"#;
        // Should insert a new top-level dependencies array before `targets:`.
        let result = insert_into_dependencies_array(
            input,
            ".package(id: \"lpmdev.acme-logger\", from: \"1.0.0\")",
            Some("targets:"),
        );
        assert!(
            result.is_ok(),
            "Should insert dependencies array when missing. Error: {:?}",
            result.err()
        );
        let content = result.unwrap();
        assert!(
            content.contains("dependencies: ["),
            "Should contain a new dependencies array"
        );
        assert!(
            content.contains("lpmdev.acme-logger"),
            "Should contain the new dependency"
        );
        // The new dependencies array should appear before targets:
        let deps_pos = content.find("dependencies: [").unwrap();
        let targets_pos = content.find("targets:").unwrap();
        assert!(
            deps_pos < targets_pos,
            "dependencies should appear before targets"
        );
    }

    #[test]
    fn test_finding1_add_registry_dependency_inserts_deps_when_missing() {
        // Verify that add_registry_dependency inserts a top-level dependencies array
        // when one doesn't exist (e.g., Swift 6.3 `swift package init` output).
        let input = r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    targets: [
        .target(name: "MyApp", dependencies: [
            .product(name: "NIOCore", package: "swift-nio"),
        ]),
    ]
)
"#;
        let tmp = std::env::temp_dir().join("test_finding1.swift");
        std::fs::write(&tmp, input).unwrap();

        let result =
            add_registry_dependency(&tmp, "lpmdev.acme-logger", "1.0.0", "Logger", "MyApp");

        let content = std::fs::read_to_string(&tmp).unwrap_or_default();
        std::fs::remove_file(&tmp).ok();

        assert!(
            result.is_ok(),
            "Should succeed by inserting dependencies array. Error: {:?}",
            result.err()
        );
        assert!(
            content.contains("lpmdev.acme-logger"),
            "Package.swift should contain the new dependency"
        );
    }

    // === Finding #2: escaped quotes break bracket matcher ===
    #[test]
    fn test_finding2_escaped_quotes_in_string() {
        let content = "dependencies: [\n    .package(url: \"test\\\"]\"),\n]";
        let open = content.find('[').unwrap();
        let close = find_matching_bracket(content, open);
        assert!(
            close.is_some(),
            "Bracket matcher should handle escaped quotes in strings"
        );
        let close = close.unwrap();
        assert_eq!(
            close,
            content.rfind(']').unwrap(),
            "Should find the actual closing bracket, not the one inside the string. Found pos {} but expected {}",
            close,
            content.rfind(']').unwrap()
        );
    }

    // === Finding #3: comments break bracket matcher ===
    #[test]
    fn test_finding3_comments_with_unmatched_brackets() {
        let content = "dependencies: [\n    // removed: ]\n    .package(url: \"https://example.com/repo.git\", from: \"1.0.0\"),\n]";
        let open = content.find('[').unwrap();
        let close = find_matching_bracket(content, open);
        assert!(
            close.is_some(),
            "Bracket matcher should skip brackets inside // comments"
        );
        let close = close.unwrap();
        assert_eq!(
            close,
            content.rfind(']').unwrap(),
            "Should find the actual closing bracket, not the one in the comment"
        );
    }

    #[test]
    fn test_finding3_block_comments_with_unmatched_brackets() {
        let content = "dependencies: [\n    /* removed: ] */\n    .package(url: \"https://example.com/repo.git\", from: \"1.0.0\"),\n]";
        let open = content.find('[').unwrap();
        let close = find_matching_bracket(content, open);
        assert!(
            close.is_some(),
            "Bracket matcher should skip /* */ comments"
        );
        let close = close.unwrap();
        assert_eq!(close, content.rfind(']').unwrap());
    }

    // === Finding #4: wrong target modified when target lacks dependencies ===
    #[test]
    fn test_finding4_target_without_deps_finds_next_targets_deps() {
        let input = r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(id: "lpmdev.acme-logger", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "FirstTarget",
            path: "Sources/First"
        ),
        .target(
            name: "SecondTarget",
            dependencies: [
                .product(name: "Existing", package: "some-pkg"),
            ]
        ),
    ]
)
"#;
        let result = insert_into_target_deps(
            input,
            "FirstTarget",
            ".product(name: \"Logger\", package: \"lpmdev.acme-logger\")",
        );

        match &result {
            Ok(content) => {
                // SecondTarget's deps section should be unchanged.
                let second_target_pos = content.find("name: \"SecondTarget\"").unwrap();
                let second_deps_start = content[second_target_pos..].find("dependencies:").unwrap();
                let section_end = (second_target_pos + second_deps_start + 200).min(content.len());
                let second_deps_section =
                    &content[second_target_pos + second_deps_start..section_end];
                assert!(
                    !second_deps_section.contains("Logger"),
                    "Should NOT insert into SecondTarget's dependencies. Got:\n{}",
                    content
                );
                // FirstTarget should have the new dependency
                let first_target_pos = content.find("name: \"FirstTarget\"").unwrap();
                let first_section_end = content.find("name: \"SecondTarget\"").unwrap();
                let first_section = &content[first_target_pos..first_section_end];
                assert!(
                    first_section.contains("Logger"),
                    "Should insert into FirstTarget. Got:\n{}",
                    content
                );
            }
            Err(_) => {
                // An error is acceptable if it correctly detects FirstTarget has no deps.
            }
        }
    }

    // === Finding #6: no validation of version/product_name ===
    #[test]
    fn test_finding6_malicious_product_name() {
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
        let tmp = std::env::temp_dir().join("test_finding6.swift");
        std::fs::write(&tmp, input).unwrap();

        let result = add_registry_dependency(
            &tmp,
            "lpmdev.acme-logger",
            "1.0.0",
            r#"Evil", package: "hack"#,
            "MyApp",
        );

        std::fs::remove_file(&tmp).ok();

        assert!(
            result.is_err(),
            "Should reject product_name containing quotes"
        );
    }

    #[test]
    fn test_finding6_malicious_version() {
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
        let tmp = std::env::temp_dir().join("test_finding6_ver.swift");
        std::fs::write(&tmp, input).unwrap();

        let result = add_registry_dependency(
            &tmp,
            "lpmdev.acme-logger",
            "1.0.0\"), .package(url: \"evil",
            "Logger",
            "MyApp",
        );

        std::fs::remove_file(&tmp).ok();

        assert!(result.is_err(), "Should reject version containing quotes");
    }

    // === Finding #11: indent assumes 4-space ===
    #[test]
    fn test_finding11_two_space_indent_empty_array() {
        let input = "// swift-tools-version: 5.9\nimport PackageDescription\n\nlet package = Package(\n  name: \"MyApp\",\n  dependencies: [],\n  targets: [\n    .target(name: \"MyApp\", dependencies: []),\n  ]\n)\n";

        let content = insert_into_dependencies_array(
            input,
            ".package(id: \"lpmdev.acme-logger\", from: \"1.0.0\")",
            Some("targets:"),
        )
        .unwrap();

        let lines: Vec<&str> = content.lines().collect();
        let deps_line_idx = lines
            .iter()
            .position(|l| l.contains("dependencies: ["))
            .expect("Should find dependencies line");
        let close_bracket_line = lines[deps_line_idx + 1..deps_line_idx + 5]
            .iter()
            .find(|l| l.trim() == "]" || l.trim() == "],")
            .expect("Should find a closing bracket line near dependencies");
        let close_indent = close_bracket_line.len() - close_bracket_line.trim_start().len();
        assert_eq!(
            close_indent, 2,
            "Closing bracket should be indented 2 spaces to match `dependencies:`. Got line: {:?}\nFull:\n{}",
            close_bracket_line, content
        );
    }

    #[test]
    fn test_finding11_tab_indent_empty_array() {
        let input = "// swift-tools-version: 5.9\nimport PackageDescription\n\nlet package = Package(\n\tname: \"MyApp\",\n\tdependencies: [],\n\ttargets: [\n\t\t.target(name: \"MyApp\", dependencies: []),\n\t]\n)\n";

        let content = insert_into_dependencies_array(
            input,
            ".package(id: \"lpmdev.acme-logger\", from: \"1.0.0\")",
            Some("targets:"),
        )
        .unwrap();

        let lines: Vec<&str> = content.lines().collect();
        let deps_line_idx = lines
            .iter()
            .position(|l| l.contains("dependencies: ["))
            .expect("Should find dependencies line");
        let close_bracket_line = lines[deps_line_idx + 1..deps_line_idx + 5]
            .iter()
            .find(|l| l.trim() == "]" || l.trim() == "],")
            .expect("Should find a closing bracket line near dependencies");
        assert!(
            close_bracket_line.starts_with('\t'),
            "Closing bracket should use tab indent, not spaces. Line: {:?}\nFull:\n{}",
            close_bracket_line,
            content
        );
    }

    // === Finding #6: validate_manifest_value unit tests ===
    #[test]
    fn test_validate_manifest_value_rejects_dangerous_chars() {
        assert!(validate_manifest_value("valid-name", "test").is_ok());
        assert!(validate_manifest_value("1.0.0", "test").is_ok());
        assert!(validate_manifest_value("MyLib", "test").is_ok());

        assert!(validate_manifest_value("has\"quote", "test").is_err());
        assert!(validate_manifest_value("has)paren", "test").is_err());
        assert!(validate_manifest_value("has(paren", "test").is_err());
        assert!(validate_manifest_value("has\nnewline", "test").is_err());
        assert!(validate_manifest_value("has\\backslash", "test").is_err());
    }

    // === Finding #4: verify insert creates deps array in target ===
    #[test]
    fn test_finding4_insert_deps_into_target_without_deps_array() {
        let input = r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(id: "lpmdev.acme-logger", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "OnlyTarget",
            path: "Sources/Only"
        ),
    ]
)
"#;
        let result = insert_into_target_deps(
            input,
            "OnlyTarget",
            ".product(name: \"Logger\", package: \"lpmdev.acme-logger\")",
        );
        assert!(
            result.is_ok(),
            "Should succeed by inserting a dependencies array. Error: {:?}",
            result.err()
        );
        let content = result.unwrap();
        assert!(
            content.contains("Logger"),
            "Should contain the new dependency"
        );
        assert!(
            content.contains("dependencies:"),
            "Should have a dependencies array"
        );
    }

    // === Additional bracket/paren matcher tests ===
    #[test]
    fn test_find_matching_paren() {
        let content = ".target(name: \"X\", path: \"Y\")";
        let open = content.find('(').unwrap();
        let close = find_matching_paren(content, open).unwrap();
        assert_eq!(&content[close..close + 1], ")");
    }

    #[test]
    fn test_find_matching_paren_with_nested() {
        let content = ".target(name: \"X\", dependencies: [.product(name: \"Y\", package: \"Z\")])";
        let open = content.find('(').unwrap();
        let close = find_matching_paren(content, open).unwrap();
        assert_eq!(close, content.len() - 1);
    }

    // === Swift 6.3 — no top-level dependencies array ===
    #[test]
    fn test_swift63_no_dependencies_array() {
        // Swift 6.3's `swift package init` generates Package.swift without a dependencies array
        let input = r#"// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "SwiftLPMTest",
    targets: [
        .executableTarget(
            name: "SwiftLPMTest"
        ),
        .testTarget(
            name: "SwiftLPMTestTests",
            dependencies: ["SwiftLPMTest"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
"#;
        let tmp = std::env::temp_dir().join("test_swift63.swift");
        std::fs::write(&tmp, input).unwrap();

        let result =
            add_registry_dependency(&tmp, "lpmdev.swiftd-hue", "1.0.2", "Hue", "SwiftLPMTest");

        let content = std::fs::read_to_string(&tmp).unwrap_or_default();
        std::fs::remove_file(&tmp).ok();

        assert!(
            result.is_ok(),
            "Should handle Swift 6.3 manifest without dependencies array. Error: {:?}",
            result.err()
        );
        assert!(
            content.contains("dependencies: ["),
            "Should have inserted a top-level dependencies array"
        );
        assert!(
            content.contains("lpmdev.swiftd-hue"),
            "Should contain the package dependency"
        );
        assert!(
            content.contains("product(name: \"Hue\""),
            "Should contain the product dependency in the target"
        );
        // Verify order: dependencies before targets
        let deps_pos = content.find("dependencies: [").unwrap();
        let targets_pos = content.find("targets:").unwrap();
        assert!(
            deps_pos < targets_pos,
            "dependencies should appear before targets in output"
        );
    }

    // === Wrapper package tests ===
    #[test]
    fn test_ensure_wrapper_package_creates_scaffold() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = ensure_wrapper_package(tmp.path()).unwrap();

        assert!(result.created);
        assert!(result.manifest_path.exists());
        let manifest = std::fs::read_to_string(&result.manifest_path).unwrap();
        assert!(manifest.contains("name: \"LPMDependencies\""));
        assert!(manifest.contains("dependencies: []"));

        let exports = tmp
            .path()
            .join("Packages/LPMDependencies/Sources/LPMDependencies/Exports.swift");
        assert!(exports.exists());
    }

    #[test]
    fn test_ensure_wrapper_package_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let first = ensure_wrapper_package(tmp.path()).unwrap();
        assert!(first.created);

        let second = ensure_wrapper_package(tmp.path()).unwrap();
        assert!(!second.created);
        assert_eq!(first.manifest_path, second.manifest_path);
    }

    #[test]
    fn test_add_wrapper_dependency() {
        let tmp = tempfile::TempDir::new().unwrap();
        let wrapper = ensure_wrapper_package(tmp.path()).unwrap();

        let edit =
            add_wrapper_dependency(&wrapper.manifest_path, "lpmdev.swiftd-hue", "1.0.2", "Hue")
                .unwrap();
        assert!(!edit.already_exists);

        let content = std::fs::read_to_string(&wrapper.manifest_path).unwrap();
        assert!(content.contains("lpmdev.swiftd-hue"));
        assert!(content.contains("product(name: \"Hue\""));

        // Verify @_exported import was added to Exports.swift
        let exports_path = tmp
            .path()
            .join("Packages/LPMDependencies/Sources/LPMDependencies/Exports.swift");
        let exports = std::fs::read_to_string(exports_path).unwrap();
        assert!(
            exports.contains("@_exported import Hue"),
            "Exports.swift should contain @_exported import Hue, got: {exports}"
        );
    }

    #[test]
    fn test_add_wrapper_dependency_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let wrapper = ensure_wrapper_package(tmp.path()).unwrap();

        let first =
            add_wrapper_dependency(&wrapper.manifest_path, "lpmdev.swiftd-hue", "1.0.2", "Hue")
                .unwrap();
        assert!(!first.already_exists);

        let second =
            add_wrapper_dependency(&wrapper.manifest_path, "lpmdev.swiftd-hue", "1.0.2", "Hue")
                .unwrap();
        assert!(second.already_exists);

        // Verify @_exported import appears only once
        let exports_path = tmp
            .path()
            .join("Packages/LPMDependencies/Sources/LPMDependencies/Exports.swift");
        let exports = std::fs::read_to_string(exports_path).unwrap();
        let count = exports.matches("@_exported import Hue").count();
        assert_eq!(count, 1, "should have exactly one @_exported import Hue");
    }

    #[test]
    fn test_add_wrapper_multiple_deps() {
        let tmp = tempfile::TempDir::new().unwrap();
        let wrapper = ensure_wrapper_package(tmp.path()).unwrap();

        add_wrapper_dependency(&wrapper.manifest_path, "lpmdev.swiftd-hue", "1.0.2", "Hue")
            .unwrap();
        add_wrapper_dependency(
            &wrapper.manifest_path,
            "lpmdev.swiftd-haptic",
            "1.0.0",
            "Haptic",
        )
        .unwrap();

        let content = std::fs::read_to_string(&wrapper.manifest_path).unwrap();
        assert!(content.contains("lpmdev.swiftd-hue"));
        assert!(content.contains("lpmdev.swiftd-haptic"));
        assert!(content.contains("product(name: \"Hue\""));
        assert!(content.contains("product(name: \"Haptic\""));

        // Verify both @_exported imports in Exports.swift
        let exports_path = tmp
            .path()
            .join("Packages/LPMDependencies/Sources/LPMDependencies/Exports.swift");
        let exports = std::fs::read_to_string(exports_path).unwrap();
        assert!(
            exports.contains("@_exported import Hue"),
            "should contain @_exported import Hue"
        );
        assert!(
            exports.contains("@_exported import Haptic"),
            "should contain @_exported import Haptic"
        );
    }
}
