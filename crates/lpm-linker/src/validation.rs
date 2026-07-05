use lpm_common::LpmError;
use std::path::{Component, Path, PathBuf};

/// Validate a self-reference package name to prevent path traversal.
///
/// Returns `true` if the name is safe to use as a directory name under `node_modules/`.
pub(crate) fn is_valid_self_ref_name(name: &str) -> bool {
    is_safe_node_modules_entry_name(name)
}

pub(crate) fn is_safe_node_modules_entry_name(name: &str) -> bool {
    if name.is_empty() || name.contains('\0') || name.contains('\\') {
        return false;
    }
    let slash_count = name.matches('/').count();
    if slash_count == 0 && name.starts_with('@') {
        return false;
    }
    if slash_count > 1 || (slash_count == 1 && !name.starts_with('@')) {
        return false;
    }
    name.split('/')
        .all(|component| !matches!(component, "" | "." | ".."))
}

pub(crate) fn filter_node_modules_entry_name(
    name: String,
    package_name: &str,
    version: &str,
    context: &str,
) -> Option<String> {
    if is_safe_node_modules_entry_name(&name) {
        Some(name)
    } else {
        tracing::warn!("skipping unsafe {context} name {name:?} for {package_name}@{version}");
        None
    }
}

pub(crate) fn ensure_real_dir(path: &Path, label: &str) -> Result<(), LpmError> {
    ensure_real_dir_with_prefix(path, label, "")
}

pub(crate) fn ensure_real_dir_with_prefix(
    path: &Path,
    label: &str,
    prefix: &str,
) -> Result<(), LpmError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| {
        LpmError::Store(format!(
            "{prefix}failed to inspect {label} directory at {}: {e}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(LpmError::Store(format!(
            "{prefix}refusing to write {label} through symlinked directory {}",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(LpmError::Store(format!(
            "{prefix}refusing to write {label} through non-directory {}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn ensure_child_dir(dir: &Path, label: &str) -> Result<(), LpmError> {
    match dir.symlink_metadata() {
        Ok(_) => ensure_real_dir(dir, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)?;
            ensure_real_dir(dir, label)
        }
        Err(error) => Err(LpmError::Store(format!(
            "failed to inspect {label} directory at {}: {error}",
            dir.display()
        ))),
    }
}

/// System binaries that packages should not shadow without warning.
const SHADOWED_BINARIES: &[&str] = &[
    "node", "npm", "npx", "sh", "bash", "zsh", "fish", "git", "curl", "wget", "sudo", "python",
    "python3", "ruby", "perl", "env", "cat", "ls", "rm", "cp", "mv", "mkdir", "chmod",
];

/// Validate a bin entry name. Returns `Ok(())` if the name is acceptable,
/// `Err(reason)` if it must be rejected entirely.
/// Logs a warning (but does not reject) for names that shadow common system binaries.
///
/// Public so user-supplied alias names (`--alias orig=alias`) can
/// reuse the same safety bar — every path on PATH should meet the
/// same sanity check regardless of whether it came from
/// `package.json` or a CLI flag.
pub fn validate_bin_name(name: &str, pkg_name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("bin name is empty".to_string());
    }
    if name.contains('\0') {
        return Err("bin name contains null byte".to_string());
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(format!(
            "bin name \"{name}\" contains path separators or traversal components"
        ));
    }
    // NTFS alternate-data-stream separator — `foo:bar` opens the ADS.
    if name.contains(':') {
        return Err(format!(
            "bin name \"{name}\" contains ':' (NTFS alternate data stream separator)"
        ));
    }
    // Windows CreateFile silently strips trailing `.` and ` `.
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(format!(
            "bin name \"{name}\" ends with a dot or space (invalid on Windows)"
        ));
    }
    // Windows reserved device names — match the stem against both ASCII
    // and Unicode-superscript digit shapes (the Win32 parser folds them
    // together before the device match).
    const RESERVED_WIN_DEVICES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
        "LPT9",
    ];
    let stem = name.split_once('.').map_or(name, |(s, _)| s);
    let stem_upper: String = stem
        .chars()
        .map(|c| match c {
            '\u{2070}' => '0',
            '\u{00B9}' => '1',
            '\u{00B2}' => '2',
            '\u{00B3}' => '3',
            '\u{2074}' => '4',
            '\u{2075}' => '5',
            '\u{2076}' => '6',
            '\u{2077}' => '7',
            '\u{2078}' => '8',
            '\u{2079}' => '9',
            other => other,
        })
        .flat_map(char::to_uppercase)
        .collect();
    if RESERVED_WIN_DEVICES.contains(&stem_upper.as_str()) {
        return Err(format!(
            "bin name \"{name}\" is a Windows reserved device name"
        ));
    }

    // Warn (don't reject) for shadowing common system binaries
    if SHADOWED_BINARIES.contains(&name) {
        tracing::warn!(
            "package \"{pkg_name}\" declares bin \"{name}\" which shadows a common system binary"
        );
    }

    Ok(())
}

/// Validate that a bin script path does not escape its package directory via path traversal.
/// Returns `Ok(canonical_target)` with the validated canonical path, or `Err(reason)`.
///
/// `pub(crate)` so the v2 bin-shim emitter enforces the same containment
/// as the v1 hoisted/isolated emitter — v2 is the default store version
/// and a malicious package's bin entry like
/// `"bin": {"x": "../../bin/sh"}` must be skipped, not materialised.
pub(crate) fn validate_bin_target(pkg_dir: &Path, script_path: &str) -> Result<PathBuf, String> {
    // Quick reject: script_path must not contain `..` components
    let joined = pkg_dir.join(script_path);
    for component in joined.components() {
        if component == Component::ParentDir {
            return Err(format!(
                "bin target \"{script_path}\" contains path traversal (\"..\")"
            ));
        }
    }

    // Canonicalize and verify containment (the target file must exist for canonicalize)
    let canonical_target = joined
        .canonicalize()
        .map_err(|e| format!("cannot resolve bin target \"{script_path}\": {e}"))?;
    let canonical_pkg = pkg_dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve package dir: {e}"))?;

    if !canonical_target.starts_with(&canonical_pkg) {
        return Err(format!(
            "bin target \"{}\" resolves outside package directory \"{}\"",
            canonical_target.display(),
            canonical_pkg.display()
        ));
    }

    Ok(canonical_target)
}
