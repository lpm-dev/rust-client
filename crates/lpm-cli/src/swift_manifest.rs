//! Package.swift editing for SE-0292 registry dependencies.
//!
//! Provides functions to:
//! - Convert LPM package names to SE-0292 identifiers
//! - Find and parse Package.swift manifests
//! - Insert registry dependencies into Package.swift
//! - Run `swift package resolve`

use lpm_common::{LpmError, PackageName};
use std::ffi::OsStr;
use std::io::Read as _;
use std::path::{Path, PathBuf};

const SWIFT_PROCESS_OUTPUT_LIMIT: usize = lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize;

/// Convert an LPM package name to an SE-0292 registry identifier.
///
/// `@lpm.dev/owner.pkg-name` → `lpmdev.owner_pkg-name`
///
/// The `_` between owner and name is the structurally unambiguous separator:
/// the LPM grammar forbids `_` in both owner and package name (enforced on
/// the server via CHECK constraints `users_username_no_underscore`,
/// `orgs_slug_no_underscore`, `packages_name_no_underscore`). SE-0292 permits
/// `_` in the name component, so the wire format is spec-legal.
pub fn lpm_to_se0292_id(name: &PackageName) -> String {
    format!("lpmdev.{}_{}", name.owner, name.name)
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
    let mut command = swift_command();
    command
        .args(["package", "dump-package"])
        .current_dir(project_dir);
    let output = run_bounded_swift_output(command, "swift package dump-package")?;

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
                .filter(|target| {
                    matches!(
                        target.get("type").and_then(|value| value.as_str()),
                        Some("regular" | "executable" | "macro")
                    )
                })
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwiftRequirement {
    UpToNextMajor(String),
    UpToNextMinor { lower: String, upper: String },
    Exact(String),
}

impl SwiftRequirement {
    fn render(&self, se0292_id: &str) -> String {
        match self {
            Self::UpToNextMajor(version) => {
                format!(".package(id: \"{se0292_id}\", from: \"{version}\")")
            }
            Self::UpToNextMinor { lower, upper } => {
                format!(".package(id: \"{se0292_id}\", \"{lower}\"..<\"{upper}\")")
            }
            Self::Exact(version) => {
                format!(".package(id: \"{se0292_id}\", exact: \"{version}\")")
            }
        }
    }

    fn version(&self) -> &str {
        match self {
            Self::UpToNextMajor(version) | Self::Exact(version) => version,
            Self::UpToNextMinor { lower, .. } => lower,
        }
    }
}

pub struct RegistryDependency<'a> {
    pub se0292_id: &'a str,
    pub requirement: SwiftRequirement,
    pub product_name: &'a str,
    pub module_names: &'a [String],
}

#[derive(Debug, Default)]
pub struct ManifestRemoval {
    pub removed: bool,
    pub product_names: Vec<String>,
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

fn validate_registry_identity(value: &str) -> Result<(), LpmError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(LpmError::Registry(format!(
            "Invalid registry identity: {value:?}"
        )));
    }
    Ok(())
}

fn validate_swift_module_name(value: &str) -> Result<(), LpmError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(LpmError::Registry(
            "Invalid Swift module name: empty".into(),
        ));
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(LpmError::Registry(format!(
            "Invalid Swift module name: {value:?}"
        )));
    }
    Ok(())
}

fn validate_regular_single_link_file(
    path: &Path,
    label: &str,
) -> Result<std::fs::Metadata, LpmError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| LpmError::Registry(format!("failed to inspect {label}: {error}")))?;
    if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing {label} that is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(LpmError::Registry(format!(
                "refusing hard-linked {label}: {}",
                path.display()
            )));
        }
    }
    Ok(metadata)
}

fn read_managed_text(path: &Path, label: &str) -> Result<String, LpmError> {
    let metadata = validate_regular_single_link_file(path, label)?;
    if metadata.len() > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
        return Err(LpmError::Registry(format!(
            "{label} exceeds the {} byte input limit: {}",
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            path.display()
        )));
    }
    lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        .map_err(|error| LpmError::Registry(format!("failed to read {label}: {error}")))
}

fn write_managed_text(path: &Path, label: &str, content: &str) -> Result<(), LpmError> {
    if path.exists() {
        validate_regular_single_link_file(path, label)?;
    }
    lpm_common::write_file_atomic(path, content)
        .map_err(|error| LpmError::Registry(format!("failed to write {label}: {error}")))
}

fn replace_managed_text(
    path: &Path,
    label: &str,
    expected: &str,
    content: &str,
) -> Result<(), LpmError> {
    let current = read_managed_text(path, label)?;
    if current != expected {
        return Err(LpmError::Registry(format!(
            "{label} changed during the operation: {}",
            path.display()
        )));
    }
    write_managed_text(path, label, content)
}

fn ensure_real_directory(path: &Path, label: &str) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_dir() {
                return Err(LpmError::Registry(format!(
                    "refusing {label} that is not a real directory: {}",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).map_err(|error| {
                LpmError::Registry(format!(
                    "failed to create {label} {}: {error}",
                    path.display()
                ))
            })?;
        }
        Err(error) => {
            return Err(LpmError::Registry(format!(
                "failed to inspect {label} {}: {error}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn sensitive_swift_environment_key(key: &OsStr) -> bool {
    let key = key.to_string_lossy().to_ascii_uppercase();
    key == "LPM_TOKEN"
        || key == "NPM_TOKEN"
        || key == "NODE_AUTH_TOKEN"
        || key == "GITHUB_TOKEN"
        || key == "GH_TOKEN"
        || key == "AWS_ACCESS_KEY_ID"
        || key == "AWS_SECRET_ACCESS_KEY"
        || key == "AWS_SESSION_TOKEN"
        || key == "GOOGLE_APPLICATION_CREDENTIALS"
        || key == "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
        || key == "ACTIONS_ID_TOKEN_REQUEST_URL"
        || key == "CI_JOB_JWT"
        || key == "CI_JOB_JWT_V2"
        || key == "LD_PRELOAD"
        || key == "LD_LIBRARY_PATH"
        || key.starts_with("DYLD_")
        || key.ends_with("_TOKEN")
        || key.ends_with("_SECRET")
        || key.ends_with("_PASSWORD")
        || key.ends_with("_CREDENTIAL")
}

pub(crate) fn sanitize_swift_environment(command: &mut std::process::Command) {
    for (key, _) in std::env::vars_os() {
        if sensitive_swift_environment_key(&key) {
            command.env_remove(key);
        }
    }
}

pub(crate) fn swift_command() -> std::process::Command {
    let mut command = std::process::Command::new("swift");
    sanitize_swift_environment(&mut command);
    command
}

struct BoundedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn read_bounded_pipe(
    mut pipe: impl std::io::Read,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    pipe.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    let exceeded = bytes.len() > limit;
    if exceeded {
        bytes.truncate(limit);
    }
    Ok((bytes, exceeded))
}

fn run_bounded_swift_output(
    mut command: std::process::Command,
    display_name: &str,
) -> Result<BoundedOutput, LpmError> {
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| LpmError::Registry(format!("failed to run {display_name}: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| LpmError::Registry(format!("failed to capture {display_name} stdout")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| LpmError::Registry(format!("failed to capture {display_name} stderr")))?;
    let stdout_reader =
        std::thread::spawn(move || read_bounded_pipe(stdout, SWIFT_PROCESS_OUTPUT_LIMIT));
    let stderr_reader =
        std::thread::spawn(move || read_bounded_pipe(stderr, SWIFT_PROCESS_OUTPUT_LIMIT));
    let status = child.wait().map_err(|error| {
        LpmError::Registry(format!("failed to wait for {display_name}: {error}"))
    })?;
    let (stdout, stdout_exceeded) = stdout_reader
        .join()
        .map_err(|_| LpmError::Registry(format!("{display_name} stdout reader panicked")))?
        .map_err(|error| {
            LpmError::Registry(format!("failed to read {display_name} stdout: {error}"))
        })?;
    let (stderr, stderr_exceeded) = stderr_reader
        .join()
        .map_err(|_| LpmError::Registry(format!("{display_name} stderr reader panicked")))?
        .map_err(|error| {
            LpmError::Registry(format!("failed to read {display_name} stderr: {error}"))
        })?;
    if stdout_exceeded || stderr_exceeded {
        return Err(LpmError::Registry(format!(
            "{display_name} output exceeded the {} byte limit",
            SWIFT_PROCESS_OUTPUT_LIMIT
        )));
    }
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

#[derive(Clone, Copy, Debug)]
struct ArgumentArray {
    open: usize,
    close: usize,
}

#[derive(Clone, Copy, Debug)]
struct CallSpan {
    start: usize,
    open: usize,
    close: usize,
}

fn skip_non_code(bytes: &[u8], mut index: usize) -> usize {
    match bytes.get(index) {
        Some(b'"') => {
            index += 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'\\' => index = (index + 2).min(bytes.len()),
                    b'"' => return index + 1,
                    _ => index += 1,
                }
            }
            index
        }
        Some(b'/') if bytes.get(index + 1) == Some(&b'/') => {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            index
        }
        Some(b'/') if bytes.get(index + 1) == Some(&b'*') => {
            index += 2;
            let mut depth = 1usize;
            while index + 1 < bytes.len() {
                if bytes[index] == b'/' && bytes[index + 1] == b'*' {
                    depth += 1;
                    index += 2;
                } else if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                    depth -= 1;
                    index += 2;
                    if depth == 0 {
                        return index;
                    }
                } else {
                    index += 1;
                }
            }
            bytes.len()
        }
        _ => index + 1,
    }
}

fn skip_space_and_comments(content: &str, mut index: usize, end: usize) -> usize {
    let bytes = content.as_bytes();
    while index < end {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes[index] == b'/' && matches!(bytes.get(index + 1), Some(b'/' | b'*')) {
            index = skip_non_code(bytes, index);
        } else {
            break;
        }
    }
    index
}

fn identifier_end(bytes: &[u8], mut index: usize, end: usize) -> usize {
    while index < end && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
        index += 1;
    }
    index
}

fn find_package_call(content: &str) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"'
            || (bytes[index] == b'/' && matches!(bytes.get(index + 1), Some(b'/' | b'*')))
        {
            index = skip_non_code(bytes, index);
            continue;
        }
        if bytes[index..].starts_with(b"Package")
            && (index == 0
                || !(bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_'))
        {
            let after = index + "Package".len();
            if after == bytes.len()
                || !(bytes[after].is_ascii_alphanumeric() || bytes[after] == b'_')
            {
                let open = skip_space_and_comments(content, after, bytes.len());
                if bytes.get(open) == Some(&b'(') {
                    return find_matching_paren(content, open).map(|close| (open, close));
                }
            }
        }
        index += 1;
    }
    None
}

fn find_direct_argument_array(
    content: &str,
    call_open: usize,
    call_close: usize,
    label: &str,
) -> Option<ArgumentArray> {
    let bytes = content.as_bytes();
    let mut index = call_open + 1;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < call_close {
        if bytes[index] == b'"'
            || (bytes[index] == b'/' && matches!(bytes.get(index + 1), Some(b'/' | b'*')))
        {
            index = skip_non_code(bytes, index);
            continue;
        }
        if paren_depth == 0
            && bracket_depth == 0
            && brace_depth == 0
            && (bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
        {
            let word_end = identifier_end(bytes, index, call_close);
            if &content[index..word_end] == label {
                let colon = skip_space_and_comments(content, word_end, call_close);
                if bytes.get(colon) == Some(&b':') {
                    let open = skip_space_and_comments(content, colon + 1, call_close);
                    if bytes.get(open) == Some(&b'[') {
                        let close = find_matching_bracket(content, open)?;
                        if close < call_close {
                            return Some(ArgumentArray { open, close });
                        }
                    }
                }
            }
            index = word_end;
            continue;
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' if paren_depth > 0 => paren_depth -= 1,
            b'[' => bracket_depth += 1,
            b']' if bracket_depth > 0 => bracket_depth -= 1,
            b'{' => brace_depth += 1,
            b'}' if brace_depth > 0 => brace_depth -= 1,
            _ => {}
        }
        index += 1;
    }
    None
}

fn find_direct_argument_label(
    content: &str,
    call_open: usize,
    call_close: usize,
    label: &str,
) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut index = call_open + 1;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < call_close {
        if bytes[index] == b'"'
            || (bytes[index] == b'/' && matches!(bytes.get(index + 1), Some(b'/' | b'*')))
        {
            index = skip_non_code(bytes, index);
            continue;
        }
        if paren_depth == 0
            && bracket_depth == 0
            && brace_depth == 0
            && (bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
        {
            let word_end = identifier_end(bytes, index, call_close);
            if &content[index..word_end] == label {
                let colon = skip_space_and_comments(content, word_end, call_close);
                if bytes.get(colon) == Some(&b':') {
                    return Some(index);
                }
            }
            index = word_end;
            continue;
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' if paren_depth > 0 => paren_depth -= 1,
            b'[' => bracket_depth += 1,
            b']' if bracket_depth > 0 => bracket_depth -= 1,
            b'{' => brace_depth += 1,
            b'}' if brace_depth > 0 => brace_depth -= 1,
            _ => {}
        }
        index += 1;
    }
    None
}

fn find_package_argument_array(content: &str, label: &str) -> Option<ArgumentArray> {
    let (open, close) = find_package_call(content)?;
    find_direct_argument_array(content, open, close, label)
}

fn parse_string_literal(content: &str, start: usize, end: usize) -> Option<(String, usize)> {
    let bytes = content.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut value = String::new();
    let mut index = start + 1;
    while index < end {
        match bytes[index] {
            b'"' => return Some((value, index + 1)),
            b'\\' => {
                index += 1;
                let escaped = *bytes.get(index)?;
                match escaped {
                    b'"' => value.push('"'),
                    b'\\' => value.push('\\'),
                    b'n' => value.push('\n'),
                    b'r' => value.push('\r'),
                    b't' => value.push('\t'),
                    _ => return None,
                }
                index += 1;
            }
            byte if byte.is_ascii() => {
                value.push(byte as char);
                index += 1;
            }
            _ => {
                let character = content[index..].chars().next()?;
                value.push(character);
                index += character.len_utf8();
            }
        }
    }
    None
}

fn find_direct_string_argument(
    content: &str,
    call_open: usize,
    call_close: usize,
    label: &str,
) -> Option<String> {
    let bytes = content.as_bytes();
    let mut index = call_open + 1;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < call_close {
        if bytes[index] == b'"'
            || (bytes[index] == b'/' && matches!(bytes.get(index + 1), Some(b'/' | b'*')))
        {
            index = skip_non_code(bytes, index);
            continue;
        }
        if paren_depth == 0
            && bracket_depth == 0
            && brace_depth == 0
            && (bytes[index].is_ascii_alphabetic() || bytes[index] == b'_')
        {
            let word_end = identifier_end(bytes, index, call_close);
            if &content[index..word_end] == label {
                let colon = skip_space_and_comments(content, word_end, call_close);
                if bytes.get(colon) == Some(&b':') {
                    let value_start = skip_space_and_comments(content, colon + 1, call_close);
                    return parse_string_literal(content, value_start, call_close)
                        .map(|(value, _)| value);
                }
            }
            index = word_end;
            continue;
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' if paren_depth > 0 => paren_depth -= 1,
            b'[' => bracket_depth += 1,
            b']' if bracket_depth > 0 => bracket_depth -= 1,
            b'{' => brace_depth += 1,
            b'}' if brace_depth > 0 => brace_depth -= 1,
            _ => {}
        }
        index += 1;
    }
    None
}

fn direct_calls_in_array(content: &str, array: ArgumentArray) -> Vec<CallSpan> {
    let bytes = content.as_bytes();
    let mut calls = Vec::new();
    let mut index = array.open + 1;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < array.close {
        if bytes[index] == b'"'
            || (bytes[index] == b'/' && matches!(bytes.get(index + 1), Some(b'/' | b'*')))
        {
            index = skip_non_code(bytes, index);
            continue;
        }
        if bracket_depth == 0 && brace_depth == 0 && bytes[index] == b'.' {
            let name_start = index + 1;
            let name_end = identifier_end(bytes, name_start, array.close);
            let open = skip_space_and_comments(content, name_end, array.close);
            if bytes.get(open) == Some(&b'(')
                && let Some(close) = find_matching_paren(content, open)
                && close < array.close
            {
                calls.push(CallSpan {
                    start: index,
                    open,
                    close,
                });
                index = close + 1;
                continue;
            }
        }
        match bytes[index] {
            b'[' => bracket_depth += 1,
            b']' if bracket_depth > 0 => bracket_depth -= 1,
            b'{' => brace_depth += 1,
            b'}' if brace_depth > 0 => brace_depth -= 1,
            _ => {}
        }
        index += 1;
    }
    calls
}

fn target_call(content: &str, target_name: &str) -> Option<CallSpan> {
    let targets = find_package_argument_array(content, "targets")?;
    direct_calls_in_array(content, targets)
        .into_iter()
        .find(|call| {
            find_direct_string_argument(content, call.open, call.close, "name").as_deref()
                == Some(target_name)
        })
}

fn replacement(content: &str, start: usize, end: usize, value: &str) -> String {
    let mut updated = String::with_capacity(content.len() - (end - start) + value.len());
    updated.push_str(&content[..start]);
    updated.push_str(value);
    updated.push_str(&content[end..]);
    updated
}

fn call_removal_span(content: &str, array: ArgumentArray, call: CallSpan) -> (usize, usize) {
    let bytes = content.as_bytes();
    let line_start = content[..call.start]
        .rfind('\n')
        .map_or(array.open + 1, |i| i + 1);
    let line_end = content[call.close + 1..array.close]
        .find('\n')
        .map_or(array.close, |offset| call.close + 1 + offset + 1);
    let before_on_line = content[line_start..call.start].trim();
    let after_on_line = content[call.close + 1..line_end]
        .trim()
        .trim_start_matches(',')
        .trim();
    if before_on_line.is_empty() && after_on_line.is_empty() {
        return (line_start, line_end);
    }

    let mut end = call.close + 1;
    end = skip_space_and_comments(content, end, array.close);
    if bytes.get(end) == Some(&b',') {
        return (call.start, end + 1);
    }
    let mut start = call.start;
    while start > array.open + 1 && bytes[start - 1].is_ascii_whitespace() {
        start -= 1;
    }
    if start > array.open + 1 && bytes[start - 1] == b',' {
        start -= 1;
    }
    (start, call.close + 1)
}

/// Add an SE-0292 registry dependency to Package.swift.
///
/// Inserts:
/// 1. `.package(id: "lpmdev.owner_pkg", from: "1.0.0")` into top-level dependencies
/// 2. `.product(name: "ProductName", package: "lpmdev.owner_pkg")` into target dependencies
///
/// Idempotent — skips if the dependency already exists.
#[cfg(test)]
fn add_registry_dependency(
    manifest_path: &Path,
    se0292_id: &str,
    version: &str,
    product_name: &str,
    target_name: &str,
) -> Result<ManifestEdit, LpmError> {
    reconcile_registry_dependencies(
        manifest_path,
        target_name,
        &[RegistryDependency {
            se0292_id,
            requirement: SwiftRequirement::UpToNextMajor(version.to_string()),
            product_name,
            module_names: &[],
        }],
    )
    .map(|mut edits| edits.remove(0))
}

pub fn reconcile_registry_dependencies(
    manifest_path: &Path,
    target_name: &str,
    dependencies: &[RegistryDependency<'_>],
) -> Result<Vec<ManifestEdit>, LpmError> {
    for dependency in dependencies {
        validate_registry_identity(dependency.se0292_id)?;
        validate_manifest_value(dependency.requirement.version(), "version")?;
        validate_manifest_value(dependency.product_name, "product_name")?;
    }
    let mut content = read_managed_text(manifest_path, "Package.swift")?;
    let original_content = content.clone();
    let mut edits = Vec::with_capacity(dependencies.len());

    for dependency in dependencies {
        let before_dependency = content.clone();
        let desired_dependency = dependency.requirement.render(dependency.se0292_id);
        let existing_dependency =
            find_package_argument_array(&content, "dependencies").and_then(|array| {
                direct_calls_in_array(&content, array)
                    .into_iter()
                    .find(|call| {
                        find_direct_string_argument(&content, call.open, call.close, "id")
                            .as_deref()
                            == Some(dependency.se0292_id)
                    })
            });
        if let Some(call) = existing_dependency {
            if content[call.start..=call.close].trim() != desired_dependency {
                content = replacement(&content, call.start, call.close + 1, &desired_dependency);
            }
        } else {
            content =
                insert_into_dependencies_array(&content, &desired_dependency, Some("targets:"))?;
        }

        let desired_product = format!(
            ".product(name: \"{}\", package: \"{}\")",
            dependency.product_name, dependency.se0292_id
        );
        let target = target_call(&content, target_name).ok_or_else(|| {
            LpmError::Registry(format!(
                "Could not find target '{target_name}' in Package.swift"
            ))
        })?;
        let existing_product =
            find_direct_argument_array(&content, target.open, target.close, "dependencies")
                .and_then(|array| {
                    direct_calls_in_array(&content, array)
                        .into_iter()
                        .find(|call| {
                            find_direct_string_argument(&content, call.open, call.close, "package")
                                .as_deref()
                                == Some(dependency.se0292_id)
                        })
                });
        if let Some(call) = existing_product {
            if content[call.start..=call.close].trim() != desired_product {
                content = replacement(&content, call.start, call.close + 1, &desired_product);
            }
        } else {
            content = insert_into_target_deps(&content, target_name, &desired_product)?;
        }
        edits.push(ManifestEdit {
            already_exists: content == before_dependency,
        });
    }

    if edits.iter().any(|edit| !edit.already_exists) {
        replace_managed_text(manifest_path, "Package.swift", &original_content, &content)?;
    }
    Ok(edits)
}

pub fn remove_registry_dependencies(
    manifest_path: &Path,
    se0292_ids: &[String],
) -> Result<Vec<ManifestRemoval>, LpmError> {
    let mut content = read_managed_text(manifest_path, "Package.swift")?;
    let original = content.clone();
    let mut removals = Vec::with_capacity(se0292_ids.len());

    for se0292_id in se0292_ids {
        validate_registry_identity(se0292_id)?;
        let mut removal = ManifestRemoval::default();
        loop {
            let Some(array) = find_package_argument_array(&content, "dependencies") else {
                break;
            };
            let Some(call) = direct_calls_in_array(&content, array)
                .into_iter()
                .find(|call| {
                    find_direct_string_argument(&content, call.open, call.close, "id").as_deref()
                        == Some(se0292_id)
                })
            else {
                break;
            };
            let (start, end) = call_removal_span(&content, array, call);
            content = replacement(&content, start, end, "");
            removal.removed = true;
        }

        loop {
            let Some(targets) = find_package_argument_array(&content, "targets") else {
                break;
            };
            let mut matching = None;
            for target in direct_calls_in_array(&content, targets) {
                let Some(dependencies) =
                    find_direct_argument_array(&content, target.open, target.close, "dependencies")
                else {
                    continue;
                };
                if let Some(product) = direct_calls_in_array(&content, dependencies)
                    .into_iter()
                    .find(|call| {
                        find_direct_string_argument(&content, call.open, call.close, "package")
                            .as_deref()
                            == Some(se0292_id)
                    })
                {
                    matching = Some((dependencies, product));
                    break;
                }
            }
            let Some((dependencies, product)) = matching else {
                break;
            };
            if let Some(name) =
                find_direct_string_argument(&content, product.open, product.close, "name")
            {
                removal.product_names.push(name);
            }
            let (start, end) = call_removal_span(&content, dependencies, product);
            content = replacement(&content, start, end, "");
            removal.removed = true;
        }
        removal.product_names.sort();
        removal.product_names.dedup();
        removals.push(removal);
    }

    if content != original {
        replace_managed_text(manifest_path, "Package.swift", &original, &content)?;
    }
    Ok(removals)
}

/// Insert an entry into the top-level `dependencies: [...]` array.
/// If `before_keyword` is Some, only consider arrays that appear before that keyword.
fn insert_into_dependencies_array(
    content: &str,
    entry: &str,
    before_keyword: Option<&str>,
) -> Result<String, LpmError> {
    let _ = before_keyword;
    let (package_open, package_close) = find_package_call(content)
        .ok_or_else(|| LpmError::Registry("Could not find Package(...) in Package.swift".into()))?;

    let (bracket_start, close_pos) =
        match find_direct_argument_array(content, package_open, package_close, "dependencies") {
            Some(array) => (array.open, array.close),
            None => {
                if let Some(kw_pos) =
                    find_direct_argument_label(content, package_open, package_close, "targets")
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
                    let line_start = content[..kw_pos].rfind('\n').map_or(kw_pos, |i| i + 1);
                    let mut new_content =
                        String::with_capacity(content.len() + new_deps.len() + 10);
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

    // Detect indentation from existing entries or derive from context
    let indent = detect_indent(content, bracket_start, close_pos);

    // Check if array is empty (only whitespace between brackets)
    let inner = content[bracket_start + 1..close_pos].trim();
    if inner.is_empty() {
        // derive closing bracket indent from the opening bracket's line
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
        .map_or(close_pos, |i| i + 1);

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
    let target = target_call(content, target_name).ok_or_else(|| {
        LpmError::Registry(format!(
            "Could not find target '{target_name}' in Package.swift"
        ))
    })?;
    let target_call_open = target.open;
    let target_call_close = target.close;
    // Search for `dependencies:` only within this target's scope
    let (bracket_start, close_pos) = if let Some(array) =
        find_direct_argument_array(content, target_call_open, target_call_close, "dependencies")
    {
        (array.open, array.close)
    } else {
        let target_indent =
            indent_one_level_from_context(content, &get_line_indent(content, target_call_open));
        let entry_indent = indent_one_level_from_context(content, &target_indent);
        let arguments = content[target_call_open + 1..target_call_close].trim_end();
        let leading_comma = if arguments.is_empty() || arguments.ends_with(',') {
            ""
        } else {
            ","
        };
        let new_deps = format!(
            "{}\n{}dependencies: [\n{}{},\n{}]",
            leading_comma, target_indent, entry_indent, entry, target_indent
        );
        let mut new_content = String::with_capacity(content.len() + new_deps.len() + 10);
        let trailing_whitespace_start = content[..target_call_close]
            .rfind(|character: char| !character.is_whitespace())
            .map_or(target_call_open + 1, |position| position + 1);
        new_content.push_str(&content[..trailing_whitespace_start]);
        new_content.push_str(&new_deps);
        new_content.push_str(&content[trailing_whitespace_start..]);
        return Ok(new_content);
    };

    let indent = detect_indent(content, bracket_start, close_pos);
    let inner = content[bracket_start + 1..close_pos].trim();

    if inner.is_empty() {
        // derive closing bracket indent from context
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
        .map_or(close_pos, |i| i + 1);

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
    let line_start = content[..pos].rfind('\n').map_or(0, |i| i + 1);
    let line = &content[line_start..pos];
    let leading = &line[..line.len() - line.trim_start().len()];
    leading.to_string()
}

/// Run `swift package resolve` in the given directory.
pub fn run_swift_resolve(project_dir: &Path) -> Result<(), LpmError> {
    let status = swift_command()
        .args(["package", "resolve"])
        .current_dir(project_dir)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| LpmError::Registry(format!("failed to run swift package resolve: {e}")))?;

    if !status.success() {
        return Err(LpmError::Registry(
            "swift package resolve failed after automatic Registry setup. See the Swift output \
             above for the actual cause. If Registry configuration or the signing certificate is \
             stale or corrupt, repair it with `lpm swift-registry --force`."
                .into(),
        ));
    }

    Ok(())
}

// ── Xcode Wrapper Package (Packages/LPMDependencies/) ──────────────────

/// Directory name for the LPM dependencies wrapper package.
pub const LPM_DEPS_PACKAGE_NAME: &str = "LPMDependencies";

/// Relative path from the project root to the wrapper package.
pub const LPM_DEPS_REL_PATH: &str = "Packages/LPMDependencies";

const LPM_DEPS_EXPORTS_HEADER: &str = "// Managed by lpm — do not edit manually.\n\
// Re-exports all LPM dependencies so they are importable from any target.\n";

/// Result of ensuring the wrapper package exists.
pub struct WrapperPackageResult {
    #[cfg(test)]
    pub created: bool,
    pub manifest_path: PathBuf,
}

/// Ensure the LPMDependencies wrapper package exists under `project_dir/Packages/LPMDependencies/`.
///
/// If it doesn't exist yet, scaffolds the directory structure with Package.swift and Exports.swift.
/// If it already exists, returns the existing manifest path.
pub fn ensure_wrapper_package(project_dir: &Path) -> Result<WrapperPackageResult, LpmError> {
    let packages_dir = project_dir.join("Packages");
    ensure_real_directory(&packages_dir, "Swift packages directory")?;
    let pkg_dir = packages_dir.join(LPM_DEPS_PACKAGE_NAME);
    ensure_real_directory(&pkg_dir, "LPMDependencies package directory")?;
    let manifest_path = pkg_dir.join("Package.swift");
    let sources_root = pkg_dir.join("Sources");
    ensure_real_directory(&sources_root, "LPMDependencies sources directory")?;
    let sources_dir = sources_root.join(LPM_DEPS_PACKAGE_NAME);
    ensure_real_directory(&sources_dir, "LPMDependencies module directory")?;
    let exports_path = sources_dir.join("Exports.swift");

    if manifest_path.exists() {
        validate_regular_single_link_file(&manifest_path, "LPMDependencies Package.swift")?;
        if exports_path.exists() {
            read_managed_text(&exports_path, "LPMDependencies Exports.swift")?;
        } else {
            write_managed_text(
                &exports_path,
                "LPMDependencies Exports.swift",
                LPM_DEPS_EXPORTS_HEADER,
            )?;
        }
        return Ok(WrapperPackageResult {
            #[cfg(test)]
            created: false,
            manifest_path,
        });
    }

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
    write_managed_text(&manifest_path, "LPMDependencies Package.swift", manifest)?;

    // Write Exports.swift — re-exports are added by add_wrapper_dependency()
    write_managed_text(
        &exports_path,
        "LPMDependencies Exports.swift",
        LPM_DEPS_EXPORTS_HEADER,
    )?;

    Ok(WrapperPackageResult {
        #[cfg(test)]
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
#[cfg(test)]
fn add_wrapper_dependency(
    manifest_path: &Path,
    se0292_id: &str,
    version: &str,
    product_name: &str,
) -> Result<ManifestEdit, LpmError> {
    let modules = vec![product_name.to_string()];
    reconcile_wrapper_dependencies(
        manifest_path,
        &[RegistryDependency {
            se0292_id,
            requirement: SwiftRequirement::UpToNextMajor(version.to_string()),
            product_name,
            module_names: &modules,
        }],
    )
    .map(|mut edits| edits.remove(0))
}

pub fn reconcile_wrapper_dependencies(
    manifest_path: &Path,
    dependencies: &[RegistryDependency<'_>],
) -> Result<Vec<ManifestEdit>, LpmError> {
    for dependency in dependencies {
        for module_name in dependency.module_names {
            validate_swift_module_name(module_name)?;
        }
    }
    let exports_path = manifest_path
        .parent()
        .ok_or_else(|| LpmError::Registry("wrapper manifest has no parent directory".into()))?
        .join("Sources")
        .join(LPM_DEPS_PACKAGE_NAME)
        .join("Exports.swift");
    let mut exports = read_managed_text(&exports_path, "LPMDependencies Exports.swift")?;
    let original_exports = exports.clone();
    let mut edits =
        reconcile_registry_dependencies(manifest_path, LPM_DEPS_PACKAGE_NAME, dependencies)?;
    for (dependency, edit) in dependencies.iter().zip(&mut edits) {
        for module_name in dependency.module_names {
            let import_line = format!(
                "@_exported import {module_name} // lpm:{}",
                dependency.se0292_id
            );
            let already_present = exports.lines().any(|line| line.trim() == import_line);
            if !already_present {
                exports.reserve(import_line.len() + 1);
                exports.push_str(&import_line);
                exports.push('\n');
                edit.already_exists = false;
            }
        }
    }
    if exports != original_exports {
        replace_managed_text(
            &exports_path,
            "LPMDependencies Exports.swift",
            &original_exports,
            &exports,
        )?;
    }
    Ok(edits)
}

pub fn remove_wrapper_dependencies(
    manifest_path: &Path,
    se0292_ids: &[String],
) -> Result<Vec<ManifestRemoval>, LpmError> {
    let exports_path = manifest_path
        .parent()
        .ok_or_else(|| LpmError::Registry("wrapper manifest has no parent directory".into()))?
        .join("Sources")
        .join(LPM_DEPS_PACKAGE_NAME)
        .join("Exports.swift");
    let exports = match exports_path.symlink_metadata() {
        Ok(_) => Some(read_managed_text(
            &exports_path,
            "LPMDependencies Exports.swift",
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(LpmError::Registry(format!(
                "failed to inspect LPMDependencies Exports.swift: {error}"
            )));
        }
    };
    let removals = remove_registry_dependencies(manifest_path, se0292_ids)?;
    if let Some(exports) = exports {
        let mut updated = String::with_capacity(exports.len());
        for line in exports.lines() {
            let tagged = se0292_ids
                .iter()
                .any(|identity| line.trim_end().ends_with(&format!("// lpm:{identity}")));
            let legacy = removals.iter().any(|removal| {
                removal
                    .product_names
                    .iter()
                    .any(|product| line.trim() == format!("@_exported import {product}"))
            });
            if !tagged && !legacy {
                updated.push_str(line);
                updated.push('\n');
            }
        }
        if updated != exports {
            replace_managed_text(
                &exports_path,
                "LPMDependencies Exports.swift",
                &exports,
                &updated,
            )?;
        }
    }
    Ok(removals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lpm_to_se0292_id() {
        let name = PackageName::parse("@lpm.dev/acme.swift-logger").unwrap();
        assert_eq!(lpm_to_se0292_id(&name), "lpmdev.acme_swift-logger");

        let name2 = PackageName::parse("@lpm.dev/neo.haptic").unwrap();
        assert_eq!(lpm_to_se0292_id(&name2), "lpmdev.neo_haptic");
    }

    /// C1 regression: `(owner=foo-bar, name=baz)` and `(owner=foo, name=bar-baz)`
    /// used to flatten to the same SE-0292 identifier under the old hyphen
    /// separator, allowing cross-tenant impersonation. With the underscore
    /// separator the two pairs MUST produce distinct identifiers — the
    /// LPM grammar forbids `_` in owner and name (enforced server-side via
    /// CHECK constraints), so the boundary between owner and name in
    /// `lpmdev.<owner>_<name>` is structurally unambiguous.
    #[test]
    fn lpm_to_se0292_id_disambiguates_hyphenated_pairs() {
        let a = PackageName {
            owner: "foo-bar".into(),
            name: "baz".into(),
        };
        let b = PackageName {
            owner: "foo".into(),
            name: "bar-baz".into(),
        };
        assert_eq!(lpm_to_se0292_id(&a), "lpmdev.foo-bar_baz");
        assert_eq!(lpm_to_se0292_id(&b), "lpmdev.foo_bar-baz");
        assert_ne!(lpm_to_se0292_id(&a), lpm_to_se0292_id(&b));
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
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "Logger",
            "MyApp",
        );

        // Can't test file I/O in unit test, so test the internal functions
        let content = insert_into_dependencies_array(
            input,
            ".package(id: \"lpmdev.acme_swift-logger\", from: \"1.0.0\")",
            Some("targets:"),
        )
        .unwrap();

        assert!(content.contains("lpmdev.acme_swift-logger"));
        assert!(content.contains(".package(url:")); // existing dep preserved

        let content = insert_into_target_deps(
            &content,
            "MyApp",
            ".product(name: \"Logger\", package: \"lpmdev.acme_swift-logger\")",
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
            ".package(id: \"lpmdev.acme_logger\", from: \"1.0.0\")",
            Some("targets:"),
        )
        .unwrap();

        assert!(content.contains("lpmdev.acme_logger"));

        let content = insert_into_target_deps(
            &content,
            "MyApp",
            ".product(name: \"Logger\", package: \"lpmdev.acme_logger\")",
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

    // === before_keyword — inserts dependencies array when missing ===
    #[test]
    fn inserts_top_level_dependencies_array_before_targets_when_missing() {
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
            ".package(id: \"lpmdev.acme_logger\", from: \"1.0.0\")",
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
            content.contains("lpmdev.acme_logger"),
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
    fn add_registry_dependency_inserts_top_level_dependencies_array_when_missing() {
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
        let tmp = std::env::temp_dir().join("swift_manifest_missing_dependencies.swift");
        std::fs::write(&tmp, input).unwrap();

        let result =
            add_registry_dependency(&tmp, "lpmdev.acme_logger", "1.0.0", "Logger", "MyApp");

        let content = std::fs::read_to_string(&tmp).unwrap_or_default();
        std::fs::remove_file(&tmp).ok();

        assert!(
            result.is_ok(),
            "Should succeed by inserting dependencies array. Error: {:?}",
            result.err()
        );
        assert!(
            content.contains("lpmdev.acme_logger"),
            "Package.swift should contain the new dependency"
        );
    }

    // === escaped quotes break bracket matcher ===
    #[test]
    fn find_matching_bracket_ignores_escaped_brackets_inside_strings() {
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

    // === comments break bracket matcher ===
    #[test]
    fn find_matching_bracket_ignores_line_comment_brackets() {
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
    fn find_matching_bracket_ignores_block_comment_brackets() {
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

    // === wrong target modified when target lacks dependencies ===
    #[test]
    fn target_dependency_insert_does_not_modify_following_target_when_array_missing() {
        let input = r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(id: "lpmdev.acme_logger", from: "1.0.0"),
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
            ".product(name: \"Logger\", package: \"lpmdev.acme_logger\")",
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

    // === no validation of version/product_name ===
    #[test]
    fn add_registry_dependency_rejects_product_name_with_quotes() {
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
        let tmp = std::env::temp_dir().join("swift_manifest_invalid_product_name.swift");
        std::fs::write(&tmp, input).unwrap();

        let result = add_registry_dependency(
            &tmp,
            "lpmdev.acme_logger",
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
    fn add_registry_dependency_rejects_version_with_quotes() {
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
        let tmp = std::env::temp_dir().join("swift_manifest_invalid_version.swift");
        std::fs::write(&tmp, input).unwrap();

        let result = add_registry_dependency(
            &tmp,
            "lpmdev.acme_logger",
            "1.0.0\"), .package(url: \"evil",
            "Logger",
            "MyApp",
        );

        std::fs::remove_file(&tmp).ok();

        assert!(result.is_err(), "Should reject version containing quotes");
    }

    // === indent assumes 4-space ===
    #[test]
    fn insert_into_dependencies_array_preserves_two_space_indent() {
        let input = "// swift-tools-version: 5.9\nimport PackageDescription\n\nlet package = Package(\n  name: \"MyApp\",\n  dependencies: [],\n  targets: [\n    .target(name: \"MyApp\", dependencies: []),\n  ]\n)\n";

        let content = insert_into_dependencies_array(
            input,
            ".package(id: \"lpmdev.acme_logger\", from: \"1.0.0\")",
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
    fn insert_into_dependencies_array_preserves_tab_indent() {
        let input = "// swift-tools-version: 5.9\nimport PackageDescription\n\nlet package = Package(\n\tname: \"MyApp\",\n\tdependencies: [],\n\ttargets: [\n\t\t.target(name: \"MyApp\", dependencies: []),\n\t]\n)\n";

        let content = insert_into_dependencies_array(
            input,
            ".package(id: \"lpmdev.acme_logger\", from: \"1.0.0\")",
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

    // === validate_manifest_value unit tests ===
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

    // === verify insert creates deps array in target ===
    #[test]
    fn insert_into_target_deps_creates_dependencies_array_when_target_lacks_one() {
        let input = r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(id: "lpmdev.acme_logger", from: "1.0.0"),
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
            ".product(name: \"Logger\", package: \"lpmdev.acme_logger\")",
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
            add_registry_dependency(&tmp, "lpmdev.swiftd_hue", "1.0.2", "Hue", "SwiftLPMTest");

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
            content.contains("lpmdev.swiftd_hue"),
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
            add_wrapper_dependency(&wrapper.manifest_path, "lpmdev.swiftd_hue", "1.0.2", "Hue")
                .unwrap();
        assert!(!edit.already_exists);

        let content = std::fs::read_to_string(&wrapper.manifest_path).unwrap();
        assert!(content.contains("lpmdev.swiftd_hue"));
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
            add_wrapper_dependency(&wrapper.manifest_path, "lpmdev.swiftd_hue", "1.0.2", "Hue")
                .unwrap();
        assert!(!first.already_exists);

        let second =
            add_wrapper_dependency(&wrapper.manifest_path, "lpmdev.swiftd_hue", "1.0.2", "Hue")
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

        add_wrapper_dependency(&wrapper.manifest_path, "lpmdev.swiftd_hue", "1.0.2", "Hue")
            .unwrap();
        add_wrapper_dependency(
            &wrapper.manifest_path,
            "lpmdev.swiftd_haptic",
            "1.0.0",
            "Haptic",
        )
        .unwrap();

        let content = std::fs::read_to_string(&wrapper.manifest_path).unwrap();
        assert!(content.contains("lpmdev.swiftd_hue"));
        assert!(content.contains("lpmdev.swiftd_haptic"));
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

    #[test]
    fn registry_dependency_is_inserted_after_products_with_nested_targets() {
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = directory.path().join("Package.swift");
        std::fs::write(
            &manifest_path,
            r#"// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Conventional",
    products: [
        .library(name: "Conventional", targets: ["Conventional"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "Conventional", dependencies: []),
    ]
)
"#,
        )
        .unwrap();

        add_registry_dependency(
            &manifest_path,
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "SwiftLogger",
            "Conventional",
        )
        .unwrap();

        let updated = std::fs::read_to_string(manifest_path).unwrap();
        assert_eq!(
            updated.matches("dependencies: [").count(),
            2,
            "install must reuse the top-level and target dependency arrays without creating a nested third array:\n{updated}"
        );
    }

    #[test]
    fn registry_dependency_comment_does_not_count_as_an_installation() {
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = directory.path().join("Package.swift");
        std::fs::write(
            &manifest_path,
            r#"// swift-tools-version: 5.9
import PackageDescription
// Documentation mentions "lpmdev.acme_swift-logger".
let package = Package(
    name: "App",
    dependencies: [],
    targets: [.target(name: "App", dependencies: [])]
)
"#,
        )
        .unwrap();

        let edit = add_registry_dependency(
            &manifest_path,
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "SwiftLogger",
            "App",
        )
        .unwrap();

        assert!(!edit.already_exists);
        let updated = std::fs::read_to_string(manifest_path).unwrap();
        assert!(updated.contains(".package(id: \"lpmdev.acme_swift-logger\", from: \"1.0.0\")"));
    }

    #[test]
    fn registry_dependency_reconciles_a_missing_target_product() {
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = directory.path().join("Package.swift");
        std::fs::write(
            &manifest_path,
            r#"// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "App",
    dependencies: [.package(id: "lpmdev.acme_swift-logger", from: "1.0.0")],
    targets: [.target(name: "App", dependencies: [])]
)
"#,
        )
        .unwrap();

        let edit = add_registry_dependency(
            &manifest_path,
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "SwiftLogger",
            "App",
        )
        .unwrap();

        assert!(!edit.already_exists);
        let updated = std::fs::read_to_string(manifest_path).unwrap();
        assert!(
            updated
                .contains(".product(name: \"SwiftLogger\", package: \"lpmdev.acme_swift-logger\")")
        );
    }

    #[test]
    fn registry_dependency_updates_an_existing_version_requirement() {
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = directory.path().join("Package.swift");
        std::fs::write(
            &manifest_path,
            r#"// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "App",
    dependencies: [.package(id: "lpmdev.acme_swift-logger", from: "1.0.0")],
    targets: [.target(name: "App", dependencies: [.product(name: "SwiftLogger", package: "lpmdev.acme_swift-logger")])]
)
"#,
        )
        .unwrap();

        let edit = add_registry_dependency(
            &manifest_path,
            "lpmdev.acme_swift-logger",
            "2.0.0",
            "SwiftLogger",
            "App",
        )
        .unwrap();

        assert!(!edit.already_exists);
        let updated = std::fs::read_to_string(manifest_path).unwrap();
        assert!(updated.contains("from: \"2.0.0\""));
        assert!(!updated.contains("from: \"1.0.0\""));
    }

    #[test]
    fn wrapper_dependency_rejects_a_source_injecting_module_name_before_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let wrapper = ensure_wrapper_package(directory.path()).unwrap();
        let manifest_before = std::fs::read(&wrapper.manifest_path).unwrap();
        let exports_path = wrapper
            .manifest_path
            .parent()
            .unwrap()
            .join("Sources/LPMDependencies/Exports.swift");
        let exports_before = std::fs::read(&exports_path).unwrap();

        let error = add_wrapper_dependency(
            &wrapper.manifest_path,
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "SwiftLogger; @_exported import Foundation",
        )
        .err()
        .expect("source-injecting module metadata must be rejected");

        assert!(error.to_string().contains("module"));
        assert_eq!(
            std::fs::read(wrapper.manifest_path).unwrap(),
            manifest_before
        );
        assert_eq!(std::fs::read(exports_path).unwrap(), exports_before);
    }

    #[cfg(unix)]
    #[test]
    fn registry_dependency_rejects_a_linked_manifest_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside.swift");
        let manifest_path = directory.path().join("Package.swift");
        let original = b"outside sentinel\n";
        std::fs::write(&outside, original).unwrap();
        symlink(&outside, &manifest_path).unwrap();

        let result = add_registry_dependency(
            &manifest_path,
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "SwiftLogger",
            "App",
        );

        assert!(result.is_err());
        assert_eq!(std::fs::read(outside).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn registry_dependency_rejects_a_hard_linked_manifest_without_touching_its_peer() {
        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside.swift");
        let manifest_path = directory.path().join("Package.swift");
        let original = r#"// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "App", dependencies: [], targets: [.target(name: "App")])
"#;
        std::fs::write(&outside, original).unwrap();
        std::fs::hard_link(&outside, &manifest_path).unwrap();

        let result = add_registry_dependency(
            &manifest_path,
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "SwiftLogger",
            "App",
        );

        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(outside).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn wrapper_creation_rejects_a_linked_packages_directory() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), project.path().join("Packages")).unwrap();

        let result = ensure_wrapper_package(project.path());

        assert!(result.is_err());
        assert!(
            !outside
                .path()
                .join("LPMDependencies/Package.swift")
                .exists()
        );
    }

    #[test]
    fn registry_dependency_rejects_an_oversized_manifest_before_parsing() {
        use std::io::{Seek as _, SeekFrom, Write as _};

        let directory = tempfile::tempdir().unwrap();
        let manifest_path = directory.path().join("Package.swift");
        let mut file = std::fs::File::create(&manifest_path).unwrap();
        file.set_len(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"// oversized").unwrap();

        let error = add_registry_dependency(
            &manifest_path,
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "SwiftLogger",
            "App",
        )
        .err()
        .expect("oversized manifests must be rejected");

        assert!(error.to_string().contains("limit"));
    }

    #[test]
    fn existing_wrapper_repairs_a_missing_exports_file() {
        let directory = tempfile::tempdir().unwrap();
        let wrapper = ensure_wrapper_package(directory.path()).unwrap();
        let exports = wrapper
            .manifest_path
            .parent()
            .unwrap()
            .join("Sources/LPMDependencies/Exports.swift");
        std::fs::remove_file(&exports).unwrap();

        ensure_wrapper_package(directory.path()).unwrap();

        assert_eq!(
            std::fs::read_to_string(exports).unwrap(),
            LPM_DEPS_EXPORTS_HEADER
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_wrapper_rejects_a_linked_exports_file_before_manifest_mutation() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside.swift");
        std::fs::write(&outside, "outside sentinel\n").unwrap();
        let wrapper = ensure_wrapper_package(directory.path()).unwrap();
        let manifest_before = std::fs::read(&wrapper.manifest_path).unwrap();
        let exports = wrapper
            .manifest_path
            .parent()
            .unwrap()
            .join("Sources/LPMDependencies/Exports.swift");
        std::fs::remove_file(&exports).unwrap();
        symlink(&outside, &exports).unwrap();

        let error = ensure_wrapper_package(directory.path())
            .err()
            .expect("linked wrapper exports must be rejected");

        assert!(error.to_string().contains("regular file"));
        assert_eq!(
            std::fs::read(wrapper.manifest_path).unwrap(),
            manifest_before
        );
        assert_eq!(
            std::fs::read_to_string(outside).unwrap(),
            "outside sentinel\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wrapper_uninstall_rejects_linked_exports_before_manifest_mutation() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let wrapper = ensure_wrapper_package(directory.path()).unwrap();
        add_wrapper_dependency(
            &wrapper.manifest_path,
            "lpmdev.acme_swift-logger",
            "1.0.0",
            "SwiftLogger",
        )
        .unwrap();
        let manifest_before = std::fs::read(&wrapper.manifest_path).unwrap();
        let exports = wrapper
            .manifest_path
            .parent()
            .unwrap()
            .join("Sources/LPMDependencies/Exports.swift");
        let outside = directory.path().join("outside.swift");
        std::fs::write(&outside, "outside sentinel\n").unwrap();
        std::fs::remove_file(&exports).unwrap();
        symlink(&outside, &exports).unwrap();

        let error = remove_wrapper_dependencies(
            &wrapper.manifest_path,
            &["lpmdev.acme_swift-logger".into()],
        )
        .expect_err("linked wrapper exports must be rejected during uninstall");

        assert!(error.to_string().contains("regular file"));
        assert_eq!(
            std::fs::read(wrapper.manifest_path).unwrap(),
            manifest_before
        );
        assert_eq!(
            std::fs::read_to_string(outside).unwrap(),
            "outside sentinel\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_swift_output_rejects_oversized_stdout() {
        let mut command = std::process::Command::new("sh");
        command.args([
            "-c",
            &format!("yes x | head -c {}", SWIFT_PROCESS_OUTPUT_LIMIT + 1),
        ]);

        let error = run_bounded_swift_output(command, "swift package dump-package")
            .err()
            .expect("oversized child output must be rejected");

        assert!(error.to_string().contains("output exceeded"));
    }
}
