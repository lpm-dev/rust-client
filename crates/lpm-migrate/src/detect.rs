//! Auto-detection of the source package manager from lockfile presence.
//!
//! Scans the project directory for known lockfiles, determines the package
//! manager kind and lockfile format version. When multiple lockfiles exist,
//! the most recently modified one wins.

use crate::{DetectedSource, SourceKind};
use lpm_common::LpmError;
use std::path::{Path, PathBuf};

/// Lockfile candidates in priority order (used when mtimes are equal).
const LOCKFILE_CANDIDATES: &[(&str, SourceKind)] = &[
    ("bun.lockb", SourceKind::Bun),
    ("bun.lock", SourceKind::Bun),
    ("pnpm-lock.yaml", SourceKind::Pnpm),
    ("yarn.lock", SourceKind::Yarn),
    ("package-lock.json", SourceKind::Npm),
];

/// Detect which package manager lockfile exists in `project_dir`.
///
/// - If multiple lockfiles exist, the most recently modified one is chosen.
/// - Warns about other lockfiles via `tracing::warn!`.
/// - Errors if no lockfile is found.
pub fn detect_source(project_dir: &Path) -> Result<DetectedSource, LpmError> {
    let mut found: Vec<(PathBuf, SourceKind, std::time::SystemTime)> = Vec::new();

    for &(filename, kind) in LOCKFILE_CANDIDATES {
        let path = project_dir.join(filename);
        if path.exists() {
            let mtime = path
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            found.push((path, kind, mtime));
        }
    }

    if found.is_empty() {
        return Err(LpmError::Script(
            "no lockfile found. Expected one of: package-lock.json, yarn.lock, \
             pnpm-lock.yaml, bun.lockb, bun.lock"
                .to_string(),
        ));
    }

    // Sort by mtime descending (most recent first). On ties, the earlier
    // position in LOCKFILE_CANDIDATES wins because sort is stable and we
    // iterate candidates in priority order.
    found.sort_by(|a, b| b.2.cmp(&a.2));

    let (chosen_path, chosen_kind, _) = &found[0];

    // Warn about other lockfiles
    for (path, kind, _) in &found[1..] {
        tracing::warn!(
            "found additional lockfile {} ({}); using {} instead",
            path.display(),
            kind,
            chosen_path.display()
        );
    }

    let version = detect_version(chosen_path, *chosen_kind)?;

    Ok(DetectedSource {
        kind: *chosen_kind,
        path: chosen_path.clone(),
        version,
    })
}

/// Detect the lockfile format version for the given lockfile.
fn detect_version(path: &Path, kind: SourceKind) -> Result<u32, LpmError> {
    match kind {
        SourceKind::Npm => detect_npm_version(path),
        SourceKind::Yarn => detect_yarn_version(path),
        SourceKind::Pnpm => detect_pnpm_version(path),
        SourceKind::Bun => detect_bun_version(path),
    }
}

/// npm: parse `lockfileVersion` from JSON.
fn detect_npm_version(path: &Path) -> Result<u32, LpmError> {
    let content = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let version = json
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32;

    Ok(version)
}

/// yarn: check for `# yarn lockfile v1` header. Yarn v1 uses a custom format;
/// Yarn Berry (v2+) uses YAML but is less common for migration.
fn detect_yarn_version(path: &Path) -> Result<u32, LpmError> {
    let content = std::fs::read_to_string(path)?;

    // Yarn Berry (v2+) lockfiles start with __metadata and contain a "cacheKey"
    if content.contains("__metadata:") {
        // Try to extract the version from __metadata
        for line in content.lines().take(20) {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("version:") {
                let ver_str = rest.trim().trim_matches('"');
                if let Ok(v) = ver_str.parse::<u32>() {
                    return Ok(v);
                }
            }
        }
        return Ok(2);
    }

    // Classic yarn v1: look for the header comment
    if content.contains("# yarn lockfile v1") {
        return Ok(1);
    }

    // Default to v1 if we can't determine
    Ok(1)
}

/// pnpm: parse `lockfileVersion` from the first few lines of YAML.
fn detect_pnpm_version(path: &Path) -> Result<u32, LpmError> {
    let content = std::fs::read_to_string(path)?;

    for line in content.lines().take(5) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("lockfileVersion:") {
            let ver_str = rest.trim().trim_matches('\'').trim_matches('"');
            // Handle formats like "9.0", "5.4", "6.0"
            if let Some(dot_pos) = ver_str.find('.') {
                if let Ok(major) = ver_str[..dot_pos].parse::<u32>() {
                    return Ok(major);
                }
            }
            // Try parsing as plain integer
            if let Ok(v) = ver_str.parse::<u32>() {
                return Ok(v);
            }
            // Try parsing as float and take the integer part
            if let Ok(v) = ver_str.parse::<f64>() {
                return Ok(v as u32);
            }
        }
    }

    Ok(5) // Default to v5 if unparseable
}

/// bun: version is determined by the extension.
/// `.lockb` = binary format (pre-1.2), `.lock` = JSON format (1.2+).
fn detect_bun_version(path: &Path) -> Result<u32, LpmError> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "lockb" => Ok(0), // Binary format
        "lock" => Ok(1),  // JSON text format
        _ => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_npm() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion": 3}"#,
        )
        .unwrap();

        let result = detect_source(dir.path()).unwrap();
        assert_eq!(result.kind, SourceKind::Npm);
        assert_eq!(result.version, 3);
    }

    #[test]
    fn detect_yarn() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("yarn.lock"),
            "# yarn lockfile v1\n\n",
        )
        .unwrap();

        let result = detect_source(dir.path()).unwrap();
        assert_eq!(result.kind, SourceKind::Yarn);
        assert_eq!(result.version, 1);
    }

    #[test]
    fn detect_pnpm() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n",
        )
        .unwrap();

        let result = detect_source(dir.path()).unwrap();
        assert_eq!(result.kind, SourceKind::Pnpm);
        assert_eq!(result.version, 9);
    }

    #[test]
    fn detect_bun_lockb() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bun.lockb"), b"\x00\x01\x02").unwrap();

        let result = detect_source(dir.path()).unwrap();
        assert_eq!(result.kind, SourceKind::Bun);
        assert_eq!(result.version, 0);
    }

    #[test]
    fn detect_bun_lock_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("bun.lock"),
            r#"{"lockfileVersion": 0, "packages": {}}"#,
        )
        .unwrap();

        let result = detect_source(dir.path()).unwrap();
        assert_eq!(result.kind, SourceKind::Bun);
        assert_eq!(result.version, 1);
    }

    #[test]
    fn prefer_most_recent() {
        let dir = tempfile::tempdir().unwrap();

        // Write npm lockfile first
        let npm_path = dir.path().join("package-lock.json");
        fs::write(&npm_path, r#"{"lockfileVersion": 3}"#).unwrap();

        // Ensure yarn.lock has a later mtime by sleeping briefly
        // and then writing it
        std::thread::sleep(std::time::Duration::from_millis(50));
        let yarn_path = dir.path().join("yarn.lock");
        fs::write(&yarn_path, "# yarn lockfile v1\n\n").unwrap();

        let result = detect_source(dir.path()).unwrap();
        assert_eq!(result.kind, SourceKind::Yarn);
    }

    #[test]
    fn no_lockfile_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = detect_source(dir.path());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("no lockfile found"));
    }

    #[test]
    fn source_kind_display() {
        assert_eq!(format!("{}", SourceKind::Npm), "npm");
        assert_eq!(format!("{}", SourceKind::Yarn), "yarn");
        assert_eq!(format!("{}", SourceKind::Pnpm), "pnpm");
        assert_eq!(format!("{}", SourceKind::Bun), "bun");
    }

    #[test]
    fn detect_pnpm_v5_float() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            "lockfileVersion: 5.4\n",
        )
        .unwrap();

        let result = detect_source(dir.path()).unwrap();
        assert_eq!(result.kind, SourceKind::Pnpm);
        assert_eq!(result.version, 5);
    }

    #[test]
    fn detect_npm_v1_default() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"name": "old-project"}"#,
        )
        .unwrap();

        let result = detect_source(dir.path()).unwrap();
        assert_eq!(result.kind, SourceKind::Npm);
        assert_eq!(result.version, 1);
    }
}
