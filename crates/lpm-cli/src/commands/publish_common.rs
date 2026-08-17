//! Shared logic for publishing to any registry.
//!
//! Contains tarball creation, file collection, README reading, and hash
//! computation. Used by both `publish.rs` (LPM) and `publish_npm.rs` (npm).

use crate::install_ui;
use lpm_common::LpmError;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAX_README_BYTES: usize = 1_000_000;

/// A file entry in the tarball.
#[derive(Debug, Clone)]
pub struct TarballFile {
    pub path: String,
    pub size: u64,
}

#[derive(Debug)]
struct TarballCandidate {
    source_path: PathBuf,
    source_root: Arc<Path>,
    archive_path: String,
}

pub(crate) struct PreparedTarball {
    pub(crate) data: Vec<u8>,
    pub(crate) files: Vec<TarballFile>,
    pub(crate) secret_scan: Option<lpm_security::behavioral::secrets::SecretScanResult>,
}

pub(crate) struct RewrittenTarball {
    pub(crate) data: std::sync::Arc<Vec<u8>>,
    pub(crate) secret_scan: Option<lpm_security::behavioral::secrets::SecretScanResult>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct TarballOptions<'a> {
    pub(crate) package_json_content: Option<&'a [u8]>,
    pub(crate) scan_secrets: bool,
}

/// Precomputed hashes for a tarball.
pub struct TarballHashes {
    /// SHA-1 hex digest.
    pub shasum: String,
    /// `sha512-{base64}` integrity string.
    pub integrity: String,
}

/// Compute SHA-1 and SHA-512 hashes for tarball data.
pub fn compute_hashes(tarball_data: &[u8]) -> TarballHashes {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use sha2::{Digest, Sha512};

    let shasum = {
        use sha1::Digest as Sha1Digest;
        let mut hasher = sha1::Sha1::new();
        hasher.update(tarball_data);
        format!("{:x}", hasher.finalize())
    };

    let integrity = {
        let mut hasher = Sha512::new();
        hasher.update(tarball_data);
        let hash = hasher.finalize();
        format!("sha512-{}", BASE64.encode(hash))
    };

    TarballHashes { shasum, integrity }
}

/// Read the README file from the project directory.
pub fn read_readme(project_dir: &Path) -> Option<String> {
    let candidates = [
        "README.md",
        "readme.md",
        "Readme.md",
        "README",
        "readme",
        "README.txt",
        "README.markdown",
    ];

    for name in candidates {
        let path = project_dir.join(name);
        let Ok(file) = std::fs::File::open(path) else {
            continue;
        };
        if let Ok(Some(content)) = read_readme_content(file) {
            return Some(content);
        }
    }
    None
}

fn read_readme_content(reader: impl Read) -> std::io::Result<Option<String>> {
    let mut bytes = Vec::with_capacity(MAX_README_BYTES + 1);
    reader
        .take((MAX_README_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() <= MAX_README_BYTES {
        return Ok(String::from_utf8(bytes).ok());
    }

    bytes.truncate(MAX_README_BYTES);
    match String::from_utf8(bytes) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.utf8_error().error_len().is_none() => {
            let valid_up_to = error.utf8_error().valid_up_to();
            let mut bytes = error.into_bytes();
            bytes.truncate(valid_up_to);
            Ok(String::from_utf8(bytes).ok())
        }
        Err(_) => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Tarball creation
// ---------------------------------------------------------------------------

/// Hard ceiling on the uncompressed tarball payload, applied
/// incrementally while assembling. M49: pre-fix the 500 MB cap was
/// only enforced AFTER the full `Vec<u8>` was built; a malicious or
/// generated huge sparse file would exhaust memory before the cap
/// fired. 500 MB matches the existing post-build limit in
/// `publish.rs` (downstream `MAX_TARBALL_SIZE`).
const MAX_UNCOMPRESSED_TARBALL_BYTES: u64 = 500 * 1024 * 1024;

/// Per-file size ceiling. The npm registry's per-file cap is well
/// below 500 MB in practice — anything past that is almost always a
/// generated artifact / mistakenly-committed binary. Rejected
/// incrementally so we don't `fs::read` the whole file before noticing.
const MAX_TARBALL_FILE_BYTES: u64 = 200 * 1024 * 1024;

/// Create a gzipped tarball from the project directory.
///
/// Respects `files` field in package.json if present.
/// Falls back to including everything except common ignores.
/// Rejects symlinks and paths that escape the project directory (S2).
#[cfg(test)]
pub fn create_tarball(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
) -> Result<(Vec<u8>, Vec<TarballFile>), LpmError> {
    let prepared = prepare_tarball(project_dir, pkg_json, TarballOptions::default())?;
    Ok((prepared.data, prepared.files))
}

pub(crate) fn prepare_tarball(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
    options: TarballOptions<'_>,
) -> Result<PreparedTarball, LpmError> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::borrow::Cow;
    use std::io::Write;

    let canonical_root = project_dir
        .canonicalize()
        .map_err(|e| LpmError::Registry(format!("cannot canonicalize project directory: {e}")))?;

    let project_files = collect_package_files(project_dir, pkg_json, &canonical_root)?;
    let mut candidates = Vec::with_capacity(project_files.len());
    let project_source_root = Arc::<Path>::from(canonical_root.clone());
    for file in project_files {
        candidates.push(TarballCandidate {
            source_path: project_dir.join(&file.path),
            source_root: Arc::clone(&project_source_root),
            archive_path: file.path,
        });
    }
    collect_bundled_dependencies(project_dir, pkg_json, &canonical_root, &mut candidates)?;
    candidates.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    candidates.dedup_by(|left, right| left.archive_path == right.archive_path);
    if candidates.is_empty() {
        return Err(LpmError::Registry(
            "no files to pack (check package.json 'files' field)".to_string(),
        ));
    }

    let mut tar_data = Vec::new();
    let mut accumulated: u64 = 0;
    let mut files = Vec::with_capacity(candidates.len());
    let mut secret_scan = options
        .scan_secrets
        .then(lpm_security::behavioral::secrets::SecretScanResult::default);
    let mut secret_scan_budget = options
        .scan_secrets
        .then(lpm_security::behavioral::secrets::SecretScanBudget::for_operation);
    {
        let mut builder = tar::Builder::new(&mut tar_data);

        for candidate in candidates {
            let full_path = &candidate.source_path;
            if !is_safe_candidate_file(full_path, candidate.source_root.as_ref())? {
                return Err(LpmError::Registry(format!(
                    "publish file changed or became unsafe while packing `{}`",
                    candidate.archive_path
                )));
            }

            // M49: enforce per-file AND running-total caps incrementally
            // so we never `fs::read` a multi-GB file or accumulate past
            // the 500 MB ceiling. Pre-fix the check ran only after
            // `create_tarball` returned, by which time the bytes were
            // already in memory.
            let file_size = if candidate.archive_path == "package.json" {
                options.package_json_content.map_or_else(
                    || std::fs::metadata(full_path).map_or(0, |metadata| metadata.len()),
                    |content| content.len() as u64,
                )
            } else {
                std::fs::metadata(full_path).map_or(0, |metadata| metadata.len())
            };
            if file_size > MAX_TARBALL_FILE_BYTES {
                return Err(LpmError::Registry(format!(
                    "file `{}` size {} exceeds per-file cap of {} bytes — \
                     remove it from the publish set or add an exclusion in \
                     package.json `files`",
                    candidate.archive_path, file_size, MAX_TARBALL_FILE_BYTES,
                )));
            }

            let content = if candidate.archive_path == "package.json" {
                options.package_json_content.map_or_else(
                    || std::fs::read(full_path).map(Cow::Owned),
                    |content| Ok(Cow::Borrowed(content)),
                )?
            } else {
                Cow::Owned(std::fs::read(full_path)?)
            };
            let actual_size = content.len() as u64;
            if actual_size > MAX_TARBALL_FILE_BYTES {
                return Err(LpmError::Registry(format!(
                    "file `{}` size {} exceeds per-file cap of {} bytes — \
                     remove it from the publish set or add an exclusion in \
                     package.json `files`",
                    candidate.archive_path, actual_size, MAX_TARBALL_FILE_BYTES,
                )));
            }

            accumulated = accumulated.saturating_add(actual_size);
            if accumulated > MAX_UNCOMPRESSED_TARBALL_BYTES {
                return Err(LpmError::Registry(format!(
                    "uncompressed tarball payload would exceed {} bytes (already at {} after `{}`) — \
                     reduce the publish set or split the package",
                    MAX_UNCOMPRESSED_TARBALL_BYTES, accumulated, candidate.archive_path,
                )));
            }

            let mut header = tar::Header::new_gnu();
            header.set_size(actual_size);
            header.set_mode(0o644);
            header.set_cksum();

            // npm tarballs have a `package/` prefix
            let tar_path = format!("package/{}", candidate.archive_path);
            builder
                .append_data(&mut header, &tar_path, content.as_ref())
                .map_err(LpmError::Io)?;

            if let Some((scan, budget)) = secret_scan.as_mut().zip(secret_scan_budget.as_mut()) {
                let mut file_scan =
                    lpm_security::behavioral::secrets::scan_file_content_with_budget(
                        content.as_ref(),
                        &candidate.archive_path,
                        budget,
                    );
                ensure_publish_secret_scan_complete(&file_scan)?;
                scan.matches.append(&mut file_scan.matches);
                scan.files_scanned += file_scan.files_scanned;
            }
            files.push(TarballFile {
                path: candidate.archive_path,
                size: actual_size,
            });
        }

        builder.finish().map_err(LpmError::Io)?;
    }

    // Gzip compress
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data)?;
    let gzipped = encoder.finish()?;

    Ok(PreparedTarball {
        data: gzipped,
        files,
        secret_scan,
    })
}

fn is_safe_candidate_file(path: &Path, source_root: &Path) -> Result<bool, LpmError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    let canonical = path.canonicalize()?;
    Ok(canonical.starts_with(source_root))
}

fn ensure_publish_secret_scan_complete(
    scan: &lpm_security::behavioral::secrets::SecretScanResult,
) -> Result<(), LpmError> {
    let Some(limit) = scan.limit_exceeded else {
        return Ok(());
    };
    let maximum = match limit {
        lpm_security::behavioral::secrets::SecretScanLimit::Files => {
            lpm_security::behavioral::secrets::SECRET_SCAN_MAX_FILES.to_string()
        }
        lpm_security::behavioral::secrets::SecretScanLimit::Bytes => format!(
            "{} MiB",
            lpm_security::behavioral::secrets::SECRET_SCAN_MAX_BYTES / (1024 * 1024)
        ),
        lpm_security::behavioral::secrets::SecretScanLimit::Findings => {
            lpm_security::behavioral::secrets::SECRET_SCAN_MAX_FINDINGS.to_string()
        }
    };
    Err(LpmError::Registry(format!(
        "publish secret scan stopped at the {maximum} {limit} limit; the artifact was not published"
    )))
}

// ---------------------------------------------------------------------------
// Symlink safety
// ---------------------------------------------------------------------------

/// Check if a filesystem entry is safe to include in the tarball.
///
/// Returns `false` (and logs a warning) if the path is a symlink or if its
/// canonical path escapes the project directory. This prevents malicious
/// symlinks from exfiltrating files outside the project (e.g., `~/.ssh/id_rsa`).
fn is_safe_entry(path: &Path, canonical_root: &Path) -> bool {
    // Use lstat (symlink_metadata) — does NOT follow symlinks
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                install_ui::warn_line(crate::install_ui::terminal_line!(
                    "skipping symlink: {}",
                    path.strip_prefix(canonical_root)
                        .unwrap_or(path)
                        .display()
                        .to_string()
                ));
                return false;
            }
        }
        Err(e) => {
            install_ui::warn_line(crate::install_ui::terminal_line!(
                "skipping {} (cannot read metadata: {})",
                path.display().to_string(),
                e.to_string()
            ));
            return false;
        }
    }

    // Verify canonical path is within project directory
    match path.canonicalize() {
        Ok(canonical) => {
            if !canonical.starts_with(canonical_root) {
                install_ui::warn_line(crate::install_ui::terminal_line!(
                    "skipping {} (resolves outside project directory)",
                    path.strip_prefix(canonical_root)
                        .unwrap_or(path)
                        .display()
                        .to_string()
                ));
                return false;
            }
        }
        Err(e) => {
            install_ui::warn_line(crate::install_ui::terminal_line!(
                "skipping {} (cannot canonicalize: {})",
                path.display().to_string(),
                e.to_string()
            ));
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// Collect files to include in the tarball.
///
/// If `files` field exists in package.json, only include those.
/// Otherwise include everything with common ignores.
fn collect_package_files(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
    canonical_root: &Path,
) -> Result<Vec<TarballFile>, LpmError> {
    let mut result = Vec::new();

    // Always include package.json
    let pkg_json_path = project_dir.join("package.json");
    if pkg_json_path.exists() && is_safe_entry(&pkg_json_path, canonical_root) {
        let meta = std::fs::symlink_metadata(&pkg_json_path)?;
        result.push(TarballFile {
            path: "package.json".to_string(),
            size: meta.len(),
        });
    }

    // Check for `files` field (explicit include list)
    if let Some(files_arr) = pkg_json.get("files").and_then(|f| f.as_array()) {
        let patterns: Vec<String> = files_arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        for pattern in &patterns {
            let glob_pattern = project_dir.join(pattern);
            let glob_str = glob_pattern.to_string_lossy();

            match glob::glob(&glob_str) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        if !is_safe_entry(&entry, canonical_root) {
                            continue;
                        }
                        if is_materialized_package_skill_path(&entry, project_dir) {
                            continue;
                        }
                        if entry.is_file() {
                            if let Ok(rel) = entry.strip_prefix(project_dir) {
                                let rel_str = rel.to_string_lossy().to_string();
                                if rel_str != "package.json" {
                                    let meta = std::fs::symlink_metadata(&entry)?;
                                    result.push(TarballFile {
                                        path: rel_str,
                                        size: meta.len(),
                                    });
                                }
                            }
                        } else if entry.is_dir() {
                            collect_dir_files(&entry, project_dir, canonical_root, &mut result)?;
                        }
                    }
                }
                Err(_) => {
                    // Treat as literal path
                    let path = project_dir.join(pattern);
                    if !is_safe_entry(&path, canonical_root) {
                        continue;
                    }
                    if is_materialized_package_skill_path(&path, project_dir) {
                        continue;
                    }
                    if path.is_file() {
                        let rel_str = pattern.to_string();
                        if rel_str != "package.json" {
                            let meta = std::fs::symlink_metadata(&path)?;
                            result.push(TarballFile {
                                path: rel_str,
                                size: meta.len(),
                            });
                        }
                    } else if path.is_dir() {
                        collect_dir_files(&path, project_dir, canonical_root, &mut result)?;
                    }
                }
            }
        }
    } else {
        // No `files` field — include everything with common ignores
        collect_all_files(project_dir, canonical_root, &mut result)?;
    }
    collect_required_manifest_files(project_dir, pkg_json, canonical_root, &mut result)?;

    // Always include README and LICENSE
    for extra in [
        "README.md",
        "readme.md",
        "LICENSE",
        "LICENSE.md",
        "CHANGELOG.md",
    ] {
        let path = project_dir.join(extra);
        if path.exists()
            && is_safe_entry(&path, canonical_root)
            && !result.iter().any(|f| f.path.eq_ignore_ascii_case(extra))
        {
            let meta = std::fs::symlink_metadata(&path)?;
            result.push(TarballFile {
                path: extra.to_string(),
                size: meta.len(),
            });
        }
    }

    result.retain(|file| !is_npm_strict_exclusion(&file.path));

    // Deduplicate by path
    let mut seen = std::collections::HashSet::new();
    result.retain(|f| seen.insert(f.path.clone()));

    Ok(result)
}

fn collect_required_manifest_files(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
    canonical_root: &Path,
    result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
    for field in ["main", "browser"] {
        if let Some(path) = pkg_json.get(field).and_then(serde_json::Value::as_str) {
            collect_required_manifest_path(project_dir, path, canonical_root, result)?;
        }
    }
    match pkg_json.get("bin") {
        Some(serde_json::Value::String(path)) => {
            collect_required_manifest_path(project_dir, path, canonical_root, result)?;
        }
        Some(serde_json::Value::Object(entries)) => {
            for path in entries.values().filter_map(serde_json::Value::as_str) {
                collect_required_manifest_path(project_dir, path, canonical_root, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_required_manifest_path(
    project_dir: &Path,
    manifest_path: &str,
    canonical_root: &Path,
    result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
    let normalized = manifest_path.replace('\\', "/");
    let mut relative_path = PathBuf::new();
    for component in Path::new(&normalized).components() {
        match component {
            std::path::Component::Normal(segment) => relative_path.push(segment),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(LpmError::Registry(format!(
                    "required publish entrypoint must be a project-relative path: {}",
                    lpm_common::sanitize_terminal_inline(manifest_path)
                )));
            }
        }
    }
    if relative_path.as_os_str().is_empty() {
        return Ok(());
    }
    let path = project_dir.join(&relative_path);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    if !is_safe_entry(&path, canonical_root) {
        return Ok(());
    }
    if metadata.is_dir() {
        return collect_dir_files(&path, project_dir, canonical_root, result);
    }
    if !metadata.is_file() {
        return Ok(());
    }
    let relative = path.strip_prefix(project_dir).map_err(|_| {
        LpmError::Registry(format!(
            "required publish entrypoint resolves outside the project: {manifest_path}"
        ))
    })?;
    result.push(TarballFile {
        path: relative.to_string_lossy().into_owned(),
        size: metadata.len(),
    });
    Ok(())
}

fn is_npm_strict_exclusion(path: &str) -> bool {
    let mut segment_count = 0;
    let mut file_name = None;
    for segment in path
        .split(['/', '\\'])
        .filter(|segment| !segment.is_empty())
    {
        if matches!(segment, ".git" | "node_modules") {
            return true;
        }
        segment_count += 1;
        file_name = Some(segment);
    }
    let Some(file_name) = file_name else {
        return false;
    };
    if matches!(file_name, ".npmrc" | ".npmignore" | ".gitignore") {
        return true;
    }
    segment_count == 1
        && matches!(
            file_name,
            "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" | "bun.lock" | "bun.lockb"
        )
}

fn collect_dir_files(
    dir: &Path,
    project_root: &Path,
    canonical_root: &Path,
    result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
    if is_materialized_package_skill_path(dir, project_root) {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if !is_safe_entry(&path, canonical_root) {
            continue;
        }

        if path.is_file() {
            if let Ok(rel) = path.strip_prefix(project_root) {
                let rel_str = rel.to_string_lossy().to_string();
                if rel_str != "package.json" {
                    let meta = std::fs::symlink_metadata(&path)?;
                    result.push(TarballFile {
                        path: rel_str,
                        size: meta.len(),
                    });
                }
            }
        } else if path.is_dir() {
            collect_dir_files(&path, project_root, canonical_root, result)?;
        }
    }
    Ok(())
}

/// Security-sensitive defaults applied in addition to project ignore rules.
const IGNORE_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "coverage",
    ".nyc_output",
    ".cache",
    ".next",
    ".nuxt",
    "private",
    "secrets",
    ".secrets",
    "credentials",
    ".credentials",
    ".vscode",
    ".idea",
];

const IGNORE_FILES: &[&str] = &[
    ".gitignore",
    ".npmignore",
    ".DS_Store",
    "Thumbs.db",
    ".env",
    ".env.local",
    ".env.live",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
    ".envrc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".netrc",
    ".pgpass",
];

fn collect_all_files(
    project_root: &Path,
    canonical_root: &Path,
    result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
    let ignore_file = if project_root.join(".npmignore").is_file() {
        Some(".npmignore")
    } else if project_root.join(".gitignore").is_file() {
        Some(".gitignore")
    } else {
        None
    };
    let mut walker = ignore::WalkBuilder::new(project_root);
    walker
        .standard_filters(false)
        .hidden(false)
        .parents(false)
        .follow_links(false)
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let Some(file_type) = entry.file_type() else {
                return true;
            };
            if !file_type.is_dir() {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            !(IGNORE_DIRS.contains(&name.as_ref()) || entry.depth() == 1 && name == ".lpm")
        });
    if let Some(ignore_file) = ignore_file {
        walker.add_custom_ignore_filename(ignore_file);
    }

    for entry in walker.build() {
        let entry = entry.map_err(|error| {
            LpmError::Registry(format!("failed to enumerate publish files: {error}"))
        })?;
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.path();
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() || !is_safe_entry(path, canonical_root) {
            continue;
        }
        if IGNORE_FILES.contains(&entry.file_name().to_string_lossy().as_ref()) {
            continue;
        }
        if let Ok(relative) = path.strip_prefix(project_root) {
            let relative = relative.to_string_lossy().into_owned();
            if relative != "package.json" {
                let metadata = std::fs::symlink_metadata(path)?;
                result.push(TarballFile {
                    path: relative,
                    size: metadata.len(),
                });
            }
        }
    }
    collect_implicit_lpm_files(
        &project_root.join(".lpm"),
        project_root,
        canonical_root,
        result,
    )?;
    Ok(())
}

fn collect_implicit_lpm_files(
    lpm_dir: &Path,
    project_root: &Path,
    canonical_root: &Path,
    result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
    let skills_dir = lpm_dir.join("skills");
    let skills_metadata = match std::fs::symlink_metadata(&skills_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    if !is_safe_entry(&skills_dir, canonical_root) || !skills_metadata.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(&skills_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_safe_entry(&path, canonical_root) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_file()
            && crate::commands::skills::author::is_authored_skill_path(&path, &skills_dir)
        {
            let rel = path.strip_prefix(project_root).map_err(|_| {
                LpmError::Registry(format!(
                    "authored package skill escaped project directory: {}",
                    path.display()
                ))
            })?;
            result.push(TarballFile {
                path: rel.to_string_lossy().into_owned(),
                size: metadata.len(),
            });
        }
    }
    Ok(())
}

fn is_materialized_package_skill_path(path: &Path, project_root: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(project_root) else {
        return false;
    };
    let mut segments = relative.iter();
    if segments.next() != Some(std::ffi::OsStr::new(".lpm"))
        || segments.next() != Some(std::ffi::OsStr::new("skills"))
    {
        return false;
    }
    let Some(package) = segments.next() else {
        return false;
    };
    crate::commands::skills::package::is_materialized_directory(
        &project_root.join(".lpm").join("skills").join(package),
    )
}

fn collect_bundled_dependencies(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
    canonical_project_root: &Path,
    result: &mut Vec<TarballCandidate>,
) -> Result<(), LpmError> {
    let names = bundled_dependency_names(pkg_json)?;
    if names.is_empty() {
        return Ok(());
    }

    let links_roots = lpm_common::LpmRoot::from_env()
        .ok()
        .map_or_else(Vec::new, |root| {
            [
                lpm_store::v2::StoreV2Paths::from_lpm_root(&root).links_root(),
                lpm_store::v2::StoreV2Paths::from_lpm_root_v3(&root).links_root(),
            ]
            .into_iter()
            .filter_map(|root| root.canonicalize().ok())
            .collect()
        });
    let wrappers_root = project_dir
        .join(".lpm")
        .join("wrappers")
        .canonicalize()
        .ok();
    let mut collector = BundledDependencyCollector {
        project_dir,
        canonical_project_root,
        wrappers_root: wrappers_root.as_deref(),
        links_roots: &links_roots,
        packed: std::collections::HashMap::with_capacity(names.len()),
        active_roots: std::collections::HashSet::with_capacity(names.len()),
        result,
    };
    for name in names {
        let source = resolve_installed_dependency(
            project_dir,
            None,
            &name,
            canonical_project_root,
            wrappers_root.as_deref(),
            &links_roots,
        )?
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "bundled dependency `{name}` is not installed in a verified project or LPM store layout; run `lpm install` before publishing"
            ))
        })?;
        collector.pack(&source.package_root, &name, &format!("node_modules/{name}"))?;
    }
    Ok(())
}

fn bundled_dependency_names(pkg_json: &serde_json::Value) -> Result<Vec<String>, LpmError> {
    let Some(raw) = pkg_json
        .get("bundledDependencies")
        .or_else(|| pkg_json.get("bundleDependencies"))
    else {
        return Ok(Vec::new());
    };

    let mut names = match raw {
        serde_json::Value::Bool(false) => Vec::new(),
        serde_json::Value::Bool(true) => {
            let mut names = Vec::new();
            if let Some(dependencies) = pkg_json
                .get("dependencies")
                .and_then(serde_json::Value::as_object)
            {
                names.extend(dependencies.keys().cloned());
            }
            names
        }
        serde_json::Value::Array(entries) => entries
            .iter()
            .map(|entry| {
                entry.as_str().map(str::to_string).ok_or_else(|| {
                    LpmError::Registry(
                        "package.json bundledDependencies entries must be package-name strings"
                            .into(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(LpmError::Registry(
                "package.json bundledDependencies must be an array or boolean".into(),
            ));
        }
    };
    names.sort();
    names.dedup();
    for name in &names {
        validate_bundle_name(name)?;
    }
    Ok(names)
}

fn validate_bundle_name(name: &str) -> Result<(), LpmError> {
    let segments = name.split('/').collect::<Vec<_>>();
    let valid = match segments.as_slice() {
        [plain] => !plain.is_empty() && *plain != "." && *plain != "..",
        [scope, package] => {
            scope.starts_with('@')
                && scope.len() > 1
                && !package.is_empty()
                && *package != "."
                && *package != ".."
        }
        _ => false,
    };
    if !valid || name.contains('\\') {
        return Err(LpmError::Registry(format!(
            "invalid bundled dependency name `{name}`"
        )));
    }
    Ok(())
}

struct ResolvedDependency {
    package_root: PathBuf,
    package_local: bool,
}

fn resolve_installed_dependency(
    project_dir: &Path,
    parent_package: Option<&Path>,
    name: &str,
    canonical_project_root: &Path,
    wrappers_root: Option<&Path>,
    links_roots: &[PathBuf],
) -> Result<Option<ResolvedDependency>, LpmError> {
    let mut candidates = Vec::with_capacity(2);
    if let Some(parent) = parent_package {
        candidates.push((parent.join("node_modules").join(name), true));
    }
    candidates.push((project_dir.join("node_modules").join(name), false));

    for (candidate, package_local) in candidates {
        let metadata = match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(LpmError::Io(error)),
        };
        let canonical = candidate.canonicalize().map_err(|error| {
            LpmError::Registry(format!(
                "bundled dependency `{name}` has an unreadable installed path {}: {error}",
                candidate.display()
            ))
        })?;
        if !canonical.starts_with(canonical_project_root)
            && !links_roots.iter().any(|root| canonical.starts_with(root))
        {
            return Err(LpmError::Registry(format!(
                "bundled dependency `{name}` resolves outside the verified project and LPM store roots: {}",
                candidate.display()
            )));
        }
        if metadata.file_type().is_symlink()
            && !wrappers_root.is_some_and(|root| canonical.starts_with(root))
            && !links_roots.iter().any(|root| canonical.starts_with(root))
        {
            return Err(LpmError::Registry(format!(
                "bundled dependency `{name}` uses an unverified project symlink: {}",
                candidate.display()
            )));
        }
        if !canonical.is_dir() {
            return Err(LpmError::Registry(format!(
                "bundled dependency `{name}` is not an installed package directory: {}",
                candidate.display()
            )));
        }
        let manifest_path = canonical.join("package.json");
        let content = lpm_common::read_text_file_capped(
            &manifest_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )?;
        let manifest = serde_json::from_str::<serde_json::Value>(&content).map_err(|error| {
            LpmError::Registry(format!(
                "bundled dependency `{name}` has an invalid package.json: {error}"
            ))
        })?;
        if manifest.get("name").and_then(|value| value.as_str()) != Some(name) {
            return Err(LpmError::Registry(format!(
                "bundled dependency `{name}` resolved to a package with a different identity"
            )));
        }
        return Ok(Some(ResolvedDependency {
            package_root: canonical,
            package_local,
        }));
    }

    Ok(None)
}

struct BundledDependencyCollector<'a> {
    project_dir: &'a Path,
    canonical_project_root: &'a Path,
    wrappers_root: Option<&'a Path>,
    links_roots: &'a [PathBuf],
    packed: std::collections::HashMap<String, PathBuf>,
    active_roots: std::collections::HashSet<PathBuf>,
    result: &'a mut Vec<TarballCandidate>,
}

impl BundledDependencyCollector<'_> {
    fn pack(
        &mut self,
        package_root: &Path,
        expected_name: &str,
        archive_root: &str,
    ) -> Result<(), LpmError> {
        if let Some(existing) = self.packed.get(archive_root) {
            if existing != package_root {
                return Err(LpmError::Registry(format!(
                    "bundled dependency archive path `{archive_root}` resolves to multiple installed packages"
                )));
            }
            return Ok(());
        }
        if self.active_roots.contains(package_root) {
            return Ok(());
        }
        self.packed
            .insert(archive_root.to_string(), package_root.to_path_buf());
        self.active_roots.insert(package_root.to_path_buf());
        let result = self.pack_active(package_root, expected_name, archive_root);
        self.active_roots.remove(package_root);
        result
    }

    fn pack_active(
        &mut self,
        package_root: &Path,
        expected_name: &str,
        archive_root: &str,
    ) -> Result<(), LpmError> {
        let manifest_path = package_root.join("package.json");
        let manifest_content = lpm_common::read_text_file_capped(
            &manifest_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )?;
        let manifest =
            serde_json::from_str::<serde_json::Value>(&manifest_content).map_err(|error| {
                LpmError::Registry(format!(
                    "bundled dependency `{expected_name}` has an invalid package.json: {error}"
                ))
            })?;
        if manifest.get("name").and_then(|value| value.as_str()) != Some(expected_name) {
            return Err(LpmError::Registry(format!(
                "bundled dependency `{expected_name}` resolved to a package with a different identity"
            )));
        }

        let source_root = Arc::<Path>::from(package_root);
        collect_bundle_tree(
            package_root,
            package_root,
            &source_root,
            archive_root,
            self.result,
        )?;

        let mut children = std::collections::BTreeMap::<String, bool>::new();
        if let Some(dependencies) = manifest
            .get("dependencies")
            .and_then(serde_json::Value::as_object)
        {
            children.extend(dependencies.keys().cloned().map(|name| (name, true)));
        }
        if let Some(optional_dependencies) = manifest
            .get("optionalDependencies")
            .and_then(serde_json::Value::as_object)
        {
            children.extend(
                optional_dependencies
                    .keys()
                    .cloned()
                    .map(|name| (name, false)),
            );
        }

        for (child, required) in children {
            validate_bundle_name(&child)?;
            let source = resolve_installed_dependency(
                self.project_dir,
                Some(package_root),
                &child,
                self.canonical_project_root,
                self.wrappers_root,
                self.links_roots,
            )?;
            let Some(source) = source else {
                if required {
                    return Err(LpmError::Registry(format!(
                        "bundled dependency `{expected_name}` requires `{child}`, but it is not installed; run `lpm install` before publishing"
                    )));
                }
                continue;
            };
            let nested_archive = if source.package_local {
                format!("{archive_root}/node_modules/{child}")
            } else {
                format!("node_modules/{child}")
            };
            self.pack(&source.package_root, &child, &nested_archive)?;
        }
        Ok(())
    }
}

fn collect_bundle_tree(
    dir: &Path,
    package_root: &Path,
    source_root: &Arc<Path>,
    archive_root: &str,
    result: &mut Vec<TarballCandidate>,
) -> Result<(), LpmError> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(LpmError::Registry(format!(
                "bundled dependency contains an unsupported symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            if name == "node_modules" || name == ".git" || name == ".lpm" {
                continue;
            }
            collect_bundle_tree(&path, package_root, source_root, archive_root, result)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(package_root).map_err(|_| {
                LpmError::Registry(format!(
                    "bundled dependency file escaped its package root: {}",
                    path.display()
                ))
            })?;
            let portable = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            result.push(TarballCandidate {
                source_path: path,
                source_root: Arc::clone(source_root),
                archive_path: format!("{archive_root}/{portable}"),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tarball name rewriting
// ---------------------------------------------------------------------------

/// Rewrite the `name` field inside the tarball's `package.json`.
///
/// npm validates that the `name` in the tarball's package.json matches the
/// top-level payload name. When publishing with a different name (e.g.,
/// `@lpm.dev/neo.multiple` → `publish-multiple-registry`), the tarball must
/// be patched. Returns the original tarball unchanged if names already match.
#[cfg(test)]
pub fn rewrite_tarball_name(
    tarball_data: &[u8],
    original_name: &str,
    target_name: &str,
) -> Result<Vec<u8>, LpmError> {
    let rewritten =
        rewrite_tarball_name_for_publish(tarball_data, original_name, target_name, false)?;
    Ok(rewritten.map_or_else(
        || tarball_data.to_vec(),
        |tarball| tarball.data.as_ref().clone(),
    ))
}

pub(crate) fn rewrite_tarball_name_for_publish(
    tarball_data: &[u8],
    original_name: &str,
    target_name: &str,
    scan_secrets: bool,
) -> Result<Option<RewrittenTarball>, LpmError> {
    if original_name == target_name {
        return Ok(None);
    }

    use flate2::Compression;
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;
    use std::io::{Read, Write};

    // Decompress
    let mut decoder = GzDecoder::new(tarball_data);
    let mut tar_data = Vec::new();
    decoder
        .read_to_end(&mut tar_data)
        .map_err(|e| LpmError::Registry(format!("failed to decompress tarball: {e}")))?;

    // Read tar entries, patch package.json, rebuild
    let mut new_tar_data = Vec::new();
    let mut secret_scan =
        scan_secrets.then(lpm_security::behavioral::secrets::SecretScanResult::default);
    let mut secret_scan_budget =
        scan_secrets.then(lpm_security::behavioral::secrets::SecretScanBudget::for_operation);
    let mut manifest_rewritten = false;
    {
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let mut builder = tar::Builder::new(&mut new_tar_data);

        for entry_result in archive.entries().map_err(LpmError::Io)? {
            let mut entry = entry_result.map_err(LpmError::Io)?;
            let path = entry
                .path()
                .map_err(LpmError::Io)?
                .to_string_lossy()
                .to_string();

            let mut content = Vec::new();
            entry.read_to_end(&mut content).map_err(LpmError::Io)?;

            if path == "package/package.json" {
                let mut pkg =
                    serde_json::from_slice::<serde_json::Value>(&content).map_err(|error| {
                        LpmError::Registry(format!(
                            "failed to parse package.json while preparing target tarball: {error}"
                        ))
                    })?;
                pkg["name"] = serde_json::json!(target_name);
                content = serde_json::to_vec_pretty(&pkg).map_err(|error| {
                    LpmError::Registry(format!(
                        "failed to serialize package.json for target {target_name}: {error}"
                    ))
                })?;
                manifest_rewritten = true;
            }

            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(entry.header().mode().unwrap_or(0o644));
            header.set_cksum();
            builder
                .append_data(&mut header, &path, content.as_slice())
                .map_err(LpmError::Io)?;

            if let Some((scan, budget)) = secret_scan.as_mut().zip(secret_scan_budget.as_mut()) {
                let scan_path = path.strip_prefix("package/").unwrap_or(&path);
                let mut file_scan =
                    lpm_security::behavioral::secrets::scan_file_content_with_budget(
                        &content, scan_path, budget,
                    );
                ensure_publish_secret_scan_complete(&file_scan)?;
                scan.matches.append(&mut file_scan.matches);
                scan.files_scanned += file_scan.files_scanned;
            }
        }

        builder.finish().map_err(LpmError::Io)?;
    }
    if !manifest_rewritten {
        return Err(LpmError::Registry(
            "publish tarball is missing package/package.json".into(),
        ));
    }

    // Recompress
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&new_tar_data)?;
    let gzipped = encoder.finish()?;

    Ok(Some(RewrittenTarball {
        data: std::sync::Arc::new(gzipped),
        secret_scan,
    }))
}

pub(crate) fn rewrite_workspace_deps_in_package_json(
    package_json_content: &[u8],
    workspace: &lpm_workspace::Workspace,
) -> Result<Option<Vec<u8>>, LpmError> {
    let content_str = String::from_utf8_lossy(package_json_content);
    if !content_str.contains("\"workspace:") && !content_str.contains("\"catalog:") {
        return Ok(None);
    }

    let Ok(mut pkg) = serde_json::from_slice::<serde_json::Value>(package_json_content) else {
        return Ok(Some(package_json_content.to_vec()));
    };
    let dep_fields = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ];

    for field in &dep_fields {
        let Some(deps_obj) = pkg.get(field).and_then(serde_json::Value::as_object) else {
            continue;
        };
        let mut deps_map: std::collections::HashMap<String, String> = deps_obj
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().unwrap_or("*").to_string()))
            .collect();

        lpm_workspace::resolve_workspace_protocol(&mut deps_map, workspace).map_err(|error| {
            LpmError::Registry(format!(
                "failed to resolve workspace: protocol in {field}: {error}"
            ))
        })?;

        if !workspace.root_package.catalogs.is_empty() {
            lpm_workspace::resolve_catalog_protocol(
                &mut deps_map,
                &workspace.root_package.catalogs,
            )
            .map_err(|error| {
                LpmError::Registry(format!(
                    "failed to resolve catalog: protocol in {field}: {error}"
                ))
            })?;
        }

        let mut resolved_deps = serde_json::Map::with_capacity(deps_obj.len());
        for name in deps_obj.keys() {
            if let Some(value) = deps_map.get(name) {
                resolved_deps.insert(name.clone(), serde_json::Value::String(value.clone()));
            }
        }
        pkg[field] = serde_json::Value::Object(resolved_deps);
    }

    serde_json::to_vec_pretty(&pkg).map(Some).map_err(|error| {
        LpmError::Registry(format!(
            "failed to serialize rewritten package.json: {error}"
        ))
    })
}

/// Rewrite `workspace:` and `catalog:` protocol references in the tarball's `package.json`.
///
/// Monorepo packages use `"workspace:*"`, `"workspace:^"`, etc. in their
/// dependencies. These are only valid locally — registries (npm, LPM, GitHub)
/// reject or can't resolve them. This function resolves workspace/catalog
/// protocols to concrete semver ranges before the tarball is published.
///
/// Must be called BEFORE hash computation and provenance generation.
/// Returns the original tarball unchanged if no protocols are found.
#[cfg(test)]
pub fn rewrite_workspace_deps_in_tarball(
    tarball_data: &[u8],
    workspace: &lpm_workspace::Workspace,
) -> Result<Vec<u8>, LpmError> {
    use flate2::Compression;
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;
    use std::io::{Read, Write};

    // First pass: check if any rewriting is needed by reading the tarball's package.json
    let mut decoder = GzDecoder::new(tarball_data);
    let mut tar_data = Vec::new();
    decoder
        .read_to_end(&mut tar_data)
        .map_err(|e| LpmError::Registry(format!("failed to decompress tarball: {e}")))?;

    let rewritten_package_json = {
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let mut rewritten = None;
        for entry_result in archive.entries().map_err(LpmError::Io)? {
            let mut entry = entry_result.map_err(LpmError::Io)?;
            let path = entry
                .path()
                .map_err(LpmError::Io)?
                .to_string_lossy()
                .to_string();
            if path == "package/package.json" {
                let mut content = Vec::new();
                entry.read_to_end(&mut content).map_err(LpmError::Io)?;
                rewritten = rewrite_workspace_deps_in_package_json(&content, workspace)?;
                break;
            }
        }
        rewritten
    };

    let Some(mut rewritten_package_json) = rewritten_package_json else {
        return Ok(tarball_data.to_vec());
    };

    // Rewrite: decompress → patch → recompress
    let mut new_tar_data = Vec::new();
    {
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let mut builder = tar::Builder::new(&mut new_tar_data);

        for entry_result in archive.entries().map_err(LpmError::Io)? {
            let mut entry = entry_result.map_err(LpmError::Io)?;
            let path = entry
                .path()
                .map_err(LpmError::Io)?
                .to_string_lossy()
                .to_string();

            let mut content = Vec::new();
            entry.read_to_end(&mut content).map_err(LpmError::Io)?;

            if path == "package/package.json" {
                std::mem::swap(&mut content, &mut rewritten_package_json);
            }

            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(entry.header().mode().unwrap_or(0o644));
            header.set_cksum();
            builder
                .append_data(&mut header, &path, content.as_slice())
                .map_err(LpmError::Io)?;
        }

        builder.finish().map_err(LpmError::Io)?;
    }

    // Recompress
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&new_tar_data)?;
    let gzipped = encoder.finish()?;

    Ok(gzipped)
}

// ---------------------------------------------------------------------------
// npm payload building (used by publish_npm.rs)
// ---------------------------------------------------------------------------

/// Construct the npm tarball download URL for a given registry.
///
/// Scoped: `{registry_url}/@scope/name/-/name-1.0.0.tgz`
/// Unscoped: `{registry_url}/pkg/-/pkg-1.0.0.tgz`
pub fn npm_tarball_url(registry_url: &str, npm_name: &str, version: &str) -> String {
    let short_name = if let Some((_scope, name)) = npm_name.split_once('/') {
        name
    } else {
        npm_name
    };
    let base = registry_url.trim_end_matches('/');
    format!("{base}/{npm_name}/-/{short_name}-{version}.tgz")
}

#[derive(Debug, Clone)]
pub(crate) struct NpmProvenanceAttachment {
    pub(crate) media_type: String,
    pub(crate) data: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NpmPayloadOptions<'a> {
    pub(crate) tag: Option<&'a str>,
    pub(crate) provenance_attachment: Option<&'a NpmProvenanceAttachment>,
}

/// Build the npm-compatible publish payload.
///
/// Takes the LPM version_data, strips LPM-specific fields, sets npm-required
/// fields, and returns a JSON value ready for PUT to the target registry.
pub(crate) fn build_npm_payload(
    registry_url: &str,
    npm_name: &str,
    version: &str,
    version_data: &serde_json::Value,
    tarball_data: &[u8],
    access: &str,
    options: NpmPayloadOptions<'_>,
) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

    let dist_tag = options.tag.unwrap_or("latest");
    let provenance_attachment = options.provenance_attachment;

    // Clone version data and strip LPM-specific fields
    let mut npm_version = version_data.clone();
    if let Some(obj) = npm_version.as_object_mut() {
        obj.remove("_qualityChecks");
        obj.remove("_qualityMeta");
        obj.remove("_npmPackMeta");
        obj.remove("_lpmConfig");
        obj.remove("_ecosystem");
        obj.remove("_swiftManifest");
        // Remove top-level readme from version (npm puts it at package level)
        obj.remove("readme");
    }

    // Set npm-specific name (may differ from LPM name)
    npm_version["name"] = serde_json::json!(npm_name);
    npm_version["_id"] = serde_json::json!(format!("{npm_name}@{version}"));

    // Recompute hashes from the actual tarball data (may differ from version_data
    // if the tarball was rewritten with a different package name)
    let hashes = compute_hashes(tarball_data);
    npm_version["dist"] = serde_json::json!({
        "shasum": hashes.shasum,
        "integrity": hashes.integrity,
        "tarball": npm_tarball_url(registry_url, npm_name, version),
    });

    // Build attachment key — must use the full package name (npm/GitHub convention).
    // npm CLI uses `{name}-{version}.tgz` with the full scoped name. GitHub Packages
    // is strict about this matching; npmjs.org is lenient.
    let tarball_key = format!("{npm_name}-{version}.tgz");
    // S8: Pre-allocate base64 string to avoid double allocation
    let mut tarball_base64 = String::with_capacity(tarball_data.len() * 4 / 3 + 4);
    BASE64.encode_string(tarball_data, &mut tarball_base64);

    let mut attachments =
        serde_json::Map::with_capacity(1 + usize::from(provenance_attachment.is_some()));
    attachments.insert(
        tarball_key,
        serde_json::json!({
            "content_type": "application/octet-stream",
            "data": tarball_base64,
            "length": tarball_data.len(),
        }),
    );
    if let Some(attachment) = provenance_attachment {
        let provenance_key = format!("{npm_name}-{version}.sigstore");
        attachments.insert(
            provenance_key,
            serde_json::json!({
                "content_type": attachment.media_type,
                "data": attachment.data,
                "length": javascript_string_length(&attachment.data),
            }),
        );
    }

    serde_json::json!({
        "_id": npm_name,
        "name": npm_name,
        "description": npm_version.get("description"),
        "access": access,
        "dist-tags": {
            dist_tag: version,
        },
        "versions": {
            version: npm_version,
        },
        "_attachments": attachments,
    })
}

fn javascript_string_length(value: &str) -> usize {
    value.encode_utf16().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tarball_contents(data: &[u8]) -> std::collections::BTreeMap<String, Vec<u8>> {
        use std::io::Read;

        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut tar_data = Vec::new();
        decoder.read_to_end(&mut tar_data).unwrap();
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let mut contents = std::collections::BTreeMap::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            contents.insert(path, bytes);
        }
        contents
    }

    fn valid_authored_skill() -> String {
        format!(
            "---\nname: package-usage\ndescription: Use the package through its supported public API.\n---\n# Package usage\n\n{}",
            "This package guidance explains the supported workflow with concrete examples and enough detail for an agent to use it correctly."
        )
    }

    fn archive_file_paths(tarball_data: &[u8]) -> std::collections::BTreeSet<String> {
        let decoder = flate2::read::GzDecoder::new(tarball_data);
        let mut archive = tar::Archive::new(decoder);
        archive
            .entries()
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                entry
                    .path()
                    .unwrap()
                    .strip_prefix("package")
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn compute_hashes_correct() {
        let data = b"hello world";
        let hashes = compute_hashes(data);

        // SHA-1 of "hello world"
        assert_eq!(hashes.shasum, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
        // SHA-512 integrity must start with sha512-
        assert!(hashes.integrity.starts_with("sha512-"));
    }

    #[test]
    fn read_readme_truncates_before_a_split_utf8_character() {
        let dir = tempfile::tempdir().unwrap();
        let mut readme = "a".repeat(999_999);
        readme.push('é');
        std::fs::write(dir.path().join("README.md"), readme).unwrap();

        let content = read_readme(dir.path()).unwrap();

        assert_eq!(content.len(), 999_999);
    }

    #[test]
    fn read_readme_content_does_not_read_past_the_prefix_limit() {
        struct ErrorsAfterPrefix {
            remaining: usize,
        }

        impl std::io::Read for ErrorsAfterPrefix {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    return Err(std::io::Error::other("reader advanced past prefix"));
                }
                let read = self.remaining.min(buffer.len());
                buffer[..read].fill(b'a');
                self.remaining -= read;
                Ok(read)
            }
        }

        let content = read_readme_content(ErrorsAfterPrefix {
            remaining: MAX_README_BYTES + 1,
        })
        .unwrap()
        .unwrap();

        assert_eq!(content.len(), MAX_README_BYTES);
    }

    #[test]
    fn create_tarball_basic() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();

        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#).unwrap();

        let (data, files) = create_tarball(project, &pkg_json).unwrap();
        assert!(!data.is_empty());

        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"package.json"));
        assert!(paths.contains(&"index.js"));
    }

    #[test]
    fn implicit_publish_includes_dist_entrypoint() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({
            "name": "dist-entrypoint",
            "version": "1.0.0",
            "main": "dist/index.js"
        });
        std::fs::create_dir_all(project.join("dist")).unwrap();
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join("dist/index.js"), "module.exports = 1;").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();

        assert!(files.iter().any(|file| file.path == "dist/index.js"));
    }

    #[test]
    fn implicit_publish_includes_build_entrypoint() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({
            "name": "build-entrypoint",
            "version": "1.0.0",
            "main": "build/index.js"
        });
        std::fs::create_dir_all(project.join("build")).unwrap();
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join("build/index.js"), "module.exports = 1;").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();

        assert!(files.iter().any(|file| file.path == "build/index.js"));
    }

    #[test]
    fn implicit_publish_applies_npmignore_rules() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({"name": "npmignore", "version": "1.0.0"});
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = 1;").unwrap();
        std::fs::write(project.join("private.txt"), "not for publication").unwrap();
        std::fs::write(project.join(".npmignore"), "private.txt\n").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();

        assert!(!files.iter().any(|file| file.path == "private.txt"));
    }

    #[test]
    fn implicit_publish_uses_gitignore_when_npmignore_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({"name": "gitignore", "version": "1.0.0"});
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = 1;").unwrap();
        std::fs::write(project.join("private.txt"), "not for publication").unwrap();
        std::fs::write(project.join(".gitignore"), "private.txt\n").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();

        assert!(!files.iter().any(|file| file.path == "private.txt"));
    }

    #[test]
    fn implicit_publish_prefers_npmignore_over_gitignore() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({"name": "ignore-precedence", "version": "1.0.0"});
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = 1;").unwrap();
        std::fs::write(project.join("private.txt"), "not for publication").unwrap();
        std::fs::write(project.join(".gitignore"), "index.js\n").unwrap();
        std::fs::write(project.join(".npmignore"), "private.txt\n").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();

        assert!(files.iter().any(|file| file.path == "index.js"));
        assert!(!files.iter().any(|file| file.path == "private.txt"));
    }

    #[test]
    fn implicit_publish_honors_npmignore_negation() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({"name": "ignore-negation", "version": "1.0.0"});
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join("private.txt"), "not for publication").unwrap();
        std::fs::write(project.join("public.txt"), "published").unwrap();
        std::fs::write(project.join(".npmignore"), "*.txt\n!public.txt\n").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();

        assert!(files.iter().any(|file| file.path == "public.txt"));
        assert!(!files.iter().any(|file| file.path == "private.txt"));
    }

    #[test]
    fn implicit_publish_applies_nested_npmignore_rules() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({"name": "nested-ignore", "version": "1.0.0"});
        std::fs::create_dir_all(project.join("subdir")).unwrap();
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join(".npmignore"), "").unwrap();
        std::fs::write(project.join("subdir/.npmignore"), "private.txt\n").unwrap();
        std::fs::write(project.join("subdir/private.txt"), "not for publication").unwrap();
        std::fs::write(project.join("subdir/public.txt"), "published").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();

        assert!(files.iter().any(|file| file.path == "subdir/public.txt"));
        assert!(!files.iter().any(|file| file.path == "subdir/private.txt"));
    }

    #[test]
    fn required_manifest_entrypoints_override_npmignore_rules() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({
            "name": "required-entrypoints",
            "version": "1.0.0",
            "main": "dist/main.js",
            "browser": "dist/browser.js",
            "bin": {"required-entrypoints": "bin/cli.js"}
        });
        std::fs::create_dir_all(project.join("dist")).unwrap();
        std::fs::create_dir_all(project.join("bin")).unwrap();
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join("dist/main.js"), "module.exports = 1;").unwrap();
        std::fs::write(project.join("dist/browser.js"), "window.value = 1;").unwrap();
        std::fs::write(project.join("bin/cli.js"), "#!/usr/bin/env node\n").unwrap();
        std::fs::write(project.join(".npmignore"), "dist/\nbin/\n").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();
        let paths = files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<std::collections::HashSet<_>>();
        let required =
            std::collections::HashSet::from(["dist/main.js", "dist/browser.js", "bin/cli.js"]);

        assert_eq!(paths.intersection(&required).count(), 3);
    }

    #[test]
    fn required_manifest_entrypoint_rejects_parent_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let manifest = serde_json::json!({
            "name": "escaping-entrypoint",
            "version": "1.0.0",
            "main": "../outside.js"
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join("outside.js"), "external bytes").unwrap();

        let error = create_tarball(&project, &manifest).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("must be a project-relative path")
        );
    }

    #[test]
    fn explicit_publish_excludes_npm_credentials_and_root_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({
            "name": "strict-exclusions",
            "version": "1.0.0",
            "files": ["index.js", ".npmrc", "package-lock.json"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = 1;").unwrap();
        std::fs::write(
            project.join(".npmrc"),
            "//registry.example/:_authToken=opaque-credential\n",
        )
        .unwrap();
        std::fs::write(project.join("package-lock.json"), "{}\n").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();
        let paths = files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<std::collections::HashSet<_>>();

        assert!(paths.contains("index.js"));
        assert!(!paths.contains(".npmrc"));
        assert!(!paths.contains("package-lock.json"));
    }

    #[test]
    fn implicit_publish_excludes_project_local_lpm_state() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::create_dir_all(project.join(".lpm/certs")).unwrap();
        std::fs::create_dir_all(project.join(".lpm/webhooks")).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();
        std::fs::write(project.join(".lpm/install-hash"), "local install state").unwrap();
        std::fs::write(
            project.join(".lpm/certs/cert.pem"),
            "local development certificate",
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/webhook-log.jsonl"),
            r#"{"authorization":"secret"}"#,
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/webhooks/request.json"),
            r#"{"cookie":"secret"}"#,
        )
        .unwrap();
        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#).unwrap();

        let (_, files) = create_tarball(project, &pkg_json).unwrap();

        assert!(
            files.iter().all(|file| !file.path.starts_with(".lpm/")),
            "implicit publish set contained project-local state: {:?}",
            files.iter().map(|file| &file.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn implicit_publish_includes_only_validator_authored_skill_files_under_lpm() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::create_dir_all(project.join(".lpm/skills/assets")).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/skills/package-usage.md"),
            valid_authored_skill(),
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/skills/author-notes.txt"),
            "not an authored package skill",
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/skills/assets/diagram.svg"),
            "<svg></svg>",
        )
        .unwrap();
        let validation =
            crate::commands::skills::author::validate_directory(&project.join(".lpm/skills"))
                .unwrap();
        assert_eq!(validation.valid_files, vec!["package-usage.md"]);
        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#).unwrap();

        let (_, files) = create_tarball(project, &pkg_json).unwrap();
        let lpm_paths = files
            .iter()
            .filter(|file| file.path.starts_with(".lpm/"))
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(lpm_paths, vec![".lpm/skills/package-usage.md"]);
    }

    #[test]
    fn create_tarball_excludes_materialized_dependency_skills() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();
        crate::commands::skills::package::materialize(
            project,
            "owner.dependency",
            Some("2.0.0"),
            &[lpm_registry::Skill {
                name: "usage".into(),
                description: None,
                version: None,
                globs: Vec::new(),
                content: Some("dependency guidance".into()),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();
        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#).unwrap();

        let (_, files) = create_tarball(project, &pkg_json).unwrap();

        assert!(
            files
                .iter()
                .all(|file| !file.path.starts_with(".lpm/skills/owner.dependency/"))
        );
    }

    #[test]
    fn create_tarball_excludes_materialized_dependency_skills_from_explicit_globs() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::write(
            project.join("package.json"),
            r#"{
  "name": "@lpm.dev/test.pkg",
  "version": "1.0.0",
  "files": [".lpm/skills/**/*"]
}"#,
        )
        .unwrap();
        crate::commands::skills::package::materialize(
            project,
            "owner.dependency",
            Some("2.0.0"),
            &[lpm_registry::Skill {
                name: "dependency-usage".into(),
                description: None,
                version: None,
                globs: Vec::new(),
                content: Some("dependency guidance".into()),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/skills/package-usage.md"),
            "publisher guidance",
        )
        .unwrap();
        let pkg_json: serde_json::Value = serde_json::from_str(
            r#"{
  "name": "@lpm.dev/test.pkg",
  "version": "1.0.0",
  "files": [".lpm/skills/**/*"]
}"#,
        )
        .unwrap();

        let (_, files) = create_tarball(project, &pkg_json).unwrap();

        assert!(
            files
                .iter()
                .any(|file| file.path == ".lpm/skills/package-usage.md"),
            "the explicit glob must retain publisher-authored skills"
        );
        assert!(
            files
                .iter()
                .all(|file| !file.path.starts_with(".lpm/skills/owner.dependency/")),
            "the explicit glob must not bypass ownership filtering"
        );
    }

    #[test]
    fn explicit_publish_can_include_lpm_state_without_including_materialized_skills() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::create_dir_all(project.join(".lpm/certs")).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{
  "name": "@lpm.dev/test.pkg",
  "version": "1.0.0",
  "files": [".lpm/certs/publisher.pem", ".lpm/skills/**/*"]
}"#,
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/certs/publisher.pem"),
            "deliberately published certificate fixture",
        )
        .unwrap();
        crate::commands::skills::package::materialize(
            project,
            "owner.dependency",
            Some("2.0.0"),
            &[lpm_registry::Skill {
                name: "dependency-usage".into(),
                description: None,
                version: None,
                globs: Vec::new(),
                content: Some("dependency guidance".into()),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/skills/package-usage.md"),
            valid_authored_skill(),
        )
        .unwrap();
        let pkg_json: serde_json::Value = serde_json::from_str(
            r#"{
  "name": "@lpm.dev/test.pkg",
  "version": "1.0.0",
  "files": [".lpm/certs/publisher.pem", ".lpm/skills/**/*"]
}"#,
        )
        .unwrap();

        let (_, files) = create_tarball(project, &pkg_json).unwrap();
        let paths = files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<std::collections::BTreeSet<_>>();

        assert!(paths.contains(".lpm/certs/publisher.pem"));
        assert!(paths.contains(".lpm/skills/package-usage.md"));
        assert!(
            paths
                .iter()
                .all(|path| !path.starts_with(".lpm/skills/owner.dependency/"))
        );
    }

    #[test]
    fn create_tarball_does_not_exclude_manifest_shaped_directories_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let fixture = project.join("fixtures/owner.package");
        std::fs::create_dir_all(&fixture).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            fixture.join(".lpm-package-skills.json"),
            r#"{"schema_version":1,"package":"owner.package","version":"1.0.0","skills":{}}"#,
        )
        .unwrap();
        std::fs::write(fixture.join("payload.txt"), "fixture").unwrap();
        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#).unwrap();

        let (_, files) = create_tarball(project, &pkg_json).unwrap();

        assert!(
            files
                .iter()
                .any(|file| file.path == "fixtures/owner.package/payload.txt")
        );
    }

    #[test]
    fn implicit_publish_keeps_only_valid_authored_skills_from_project_lpm_state() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::create_dir_all(project.join(".lpm/skills/nested")).unwrap();
        std::fs::create_dir_all(project.join(".lpm/certs")).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"@lpm.dev/test.pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            project.join(".lpm/skills/authored.md"),
            format!(
                "---\nname: authored\ndescription: Complete authored guidance\n---\n# Usage\n\n{}",
                "Use this package safely with concrete steps and examples. ".repeat(4)
            ),
        )
        .unwrap();
        std::fs::write(project.join(".lpm/skills/nested/ignored.md"), "ignored").unwrap();
        std::fs::write(project.join(".lpm/certs/lpm.der"), "private certificate").unwrap();
        std::fs::write(project.join(".lpm/install-hash"), "state").unwrap();
        std::fs::write(project.join(".lpm/webhook.log"), "runtime log").unwrap();
        std::fs::create_dir_all(project.join("fixtures/.lpm/skills")).unwrap();
        std::fs::write(project.join("fixtures/.lpm/skills/example.txt"), "fixture").unwrap();

        let pkg = serde_json::json!({"name":"@lpm.dev/test.pkg","version":"1.0.0"});
        let (tarball, files) = create_tarball(project, &pkg).unwrap();
        let paths = files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        let archive = tarball_contents(&tarball);

        assert!(paths.contains(&".lpm/skills/authored.md"));
        assert!(
            !paths
                .iter()
                .any(|path| { path.starts_with(".lpm/") && *path != ".lpm/skills/authored.md" })
        );
        assert!(paths.contains(&"fixtures/.lpm/skills/example.txt"));
        assert!(archive.contains_key("package/.lpm/skills/authored.md"));
        assert!(
            archive.keys().all(|path| !path.starts_with("package/.lpm/")
                || path == "package/.lpm/skills/authored.md")
        );
    }

    #[test]
    fn bundled_dependencies_include_direct_and_transitive_installed_content() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::create_dir_all(project.join("node_modules/foo")).unwrap();
        std::fs::create_dir_all(project.join("node_modules/bar")).unwrap();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "dependencies": {"foo": "1.0.0"},
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(
            project.join("node_modules/foo/package.json"),
            r#"{"name":"foo","version":"1.0.0","dependencies":{"bar":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(project.join("node_modules/foo/index.js"), "foo").unwrap();
        std::fs::write(
            project.join("node_modules/bar/package.json"),
            r#"{"name":"bar","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("node_modules/bar/index.js"), "bar").unwrap();

        let (tarball, files) = create_tarball(project, &manifest).unwrap();
        let paths = files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"node_modules/foo/package.json"));
        assert!(paths.contains(&"node_modules/foo/index.js"));
        assert!(paths.contains(&"node_modules/bar/package.json"));
        assert!(paths.contains(&"node_modules/bar/index.js"));
        let archive = tarball_contents(&tarball);
        assert_eq!(archive["package/node_modules/foo/index.js"], b"foo");
        assert_eq!(archive["package/node_modules/bar/index.js"], b"bar");
    }

    #[cfg(unix)]
    fn assert_bundled_dependency_supports_virtual_links_layout(
        store_version: lpm_store::StoreVersion,
    ) {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(&lpm_home);
        let store_paths = match store_version {
            lpm_store::StoreVersion::V3 => lpm_store::v2::StoreV2Paths::from_lpm_root_v3(&lpm_root),
            lpm_store::StoreVersion::V2 => lpm_store::v2::StoreV2Paths::from_lpm_root(&lpm_root),
            lpm_store::StoreVersion::V1 => unreachable!("v1 has no virtual links layout"),
        };
        let package_root = store_paths
            .links_root()
            .join("foo@1.0.0+0000000000000000")
            .join("node_modules")
            .join("foo");
        std::fs::create_dir_all(&package_root).unwrap();
        std::fs::write(
            package_root.join("package.json"),
            r#"{"name":"foo","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(package_root.join("index.js"), "isolated").unwrap();
        symlink(&package_root, project.join("node_modules/foo")).unwrap();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "dependencies": {"foo": "1.0.0"},
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([("LPM_HOME", lpm_home.as_os_str().to_owned())]);

        let (tarball, _) = create_tarball(&project, &manifest).unwrap();

        assert_eq!(
            tarball_contents(&tarball)["package/node_modules/foo/index.js"],
            b"isolated"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bundled_dependency_supports_the_default_v2_isolated_links_layout() {
        assert_bundled_dependency_supports_virtual_links_layout(lpm_store::StoreVersion::V2);
    }

    #[cfg(unix)]
    #[test]
    fn bundled_dependency_supports_the_experimental_v3_isolated_links_layout() {
        assert_bundled_dependency_supports_virtual_links_layout(lpm_store::StoreVersion::V3);
    }

    #[cfg(unix)]
    #[test]
    fn isolated_transitive_bundles_preserve_package_local_dependency_paths() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        let store_paths =
            lpm_store::v2::StoreV2Paths::from_lpm_root(&lpm_common::LpmRoot::from_dir(&lpm_home));
        let foo_root = store_paths
            .links_root()
            .join("foo@1.0.0+0000000000000000")
            .join("node_modules")
            .join("foo");
        let bar_root = store_paths
            .links_root()
            .join("bar@2.0.0+0000000000000000")
            .join("node_modules")
            .join("bar");
        std::fs::create_dir_all(foo_root.join("node_modules")).unwrap();
        std::fs::create_dir_all(&bar_root).unwrap();
        std::fs::write(
            foo_root.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","dependencies":{"bar":"2.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            bar_root.join("package.json"),
            r#"{"name":"bar","version":"2.0.0"}"#,
        )
        .unwrap();
        std::fs::write(bar_root.join("index.js"), "nested isolated").unwrap();
        symlink(&bar_root, foo_root.join("node_modules/bar")).unwrap();
        symlink(&foo_root, project.join("node_modules/foo")).unwrap();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([("LPM_HOME", lpm_home.as_os_str().to_owned())]);

        let (tarball, _) = create_tarball(&project, &manifest).unwrap();
        let archive = tarball_contents(&tarball);

        assert_eq!(
            archive["package/node_modules/foo/node_modules/bar/index.js"],
            b"nested isolated"
        );
        assert!(!archive.contains_key("package/node_modules/bar/index.js"));
    }

    #[cfg(unix)]
    #[test]
    fn isolated_cyclic_bundled_dependencies_terminate_without_duplicate_ancestors() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        let store_paths =
            lpm_store::v2::StoreV2Paths::from_lpm_root(&lpm_common::LpmRoot::from_dir(&lpm_home));
        let foo_root = store_paths
            .links_root()
            .join("foo@1.0.0+0000000000000000")
            .join("node_modules")
            .join("foo");
        let bar_root = store_paths
            .links_root()
            .join("bar@1.0.0+0000000000000000")
            .join("node_modules")
            .join("bar");
        std::fs::create_dir_all(foo_root.join("node_modules")).unwrap();
        std::fs::create_dir_all(bar_root.join("node_modules")).unwrap();
        std::fs::write(
            foo_root.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","dependencies":{"bar":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(foo_root.join("index.js"), "foo").unwrap();
        std::fs::write(
            bar_root.join("package.json"),
            r#"{"name":"bar","version":"1.0.0","dependencies":{"foo":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(bar_root.join("index.js"), "bar").unwrap();
        symlink(&bar_root, foo_root.join("node_modules/bar")).unwrap();
        symlink(&foo_root, bar_root.join("node_modules/foo")).unwrap();
        symlink(&foo_root, project.join("node_modules/foo")).unwrap();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([("LPM_HOME", lpm_home.as_os_str().to_owned())]);

        let (tarball, _) = create_tarball(&project, &manifest).unwrap();
        let archive = tarball_contents(&tarball);

        assert_eq!(archive["package/node_modules/foo/index.js"], b"foo");
        assert_eq!(
            archive["package/node_modules/foo/node_modules/bar/index.js"],
            b"bar"
        );
        assert!(
            archive
                .keys()
                .all(|path| !path.contains("node_modules/bar/node_modules/foo/"))
        );
    }

    #[test]
    fn unavailable_optional_transitive_dependency_does_not_break_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let package_root = project.join("node_modules/foo");
        std::fs::create_dir_all(&package_root).unwrap();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(
            package_root.join("package.json"),
            r#"{"name":"foo","version":"1.0.0","optionalDependencies":{"native-addon":"1"}}"#,
        )
        .unwrap();
        std::fs::write(package_root.join("index.js"), "foo").unwrap();

        let (_, files) = create_tarball(project, &manifest).unwrap();

        assert!(
            files
                .iter()
                .any(|file| file.path == "node_modules/foo/index.js")
        );
    }

    #[test]
    fn implicit_publish_does_not_filter_nested_lpm_named_fixture_paths() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::create_dir_all(project.join("fixtures/.lpm/certs")).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            project.join("fixtures/.lpm/certs/cert.pem"),
            "published test fixture",
        )
        .unwrap();
        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#).unwrap();

        let (_, files) = create_tarball(project, &pkg_json).unwrap();

        assert!(
            files
                .iter()
                .any(|file| file.path == "fixtures/.lpm/certs/cert.pem")
        );
    }

    #[test]
    fn bundled_dependency_bytes_are_included_in_final_secret_scanning() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let package_root = project.join("node_modules/foo");
        std::fs::create_dir_all(&package_root).unwrap();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(
            package_root.join("package.json"),
            r#"{"name":"foo","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            package_root.join("index.js"),
            r#"const password = "not-a-real-bundled-secret-fixture";"#,
        )
        .unwrap();

        let prepared = prepare_tarball(
            project,
            &manifest,
            TarballOptions {
                package_json_content: None,
                scan_secrets: true,
            },
        )
        .unwrap();
        let scan = prepared.secret_scan.unwrap();

        assert!(
            scan.matches
                .iter()
                .any(|secret| secret.description.contains("node_modules/foo/index.js"))
        );
    }

    #[test]
    fn publish_secret_scan_rejects_more_than_ten_thousand_findings() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "files": ["index.js"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let secret = format!("sk_{}_{}", "live", "F".repeat(20));
        let mut content = String::with_capacity((secret.len() + 1) * 10_001);
        for _ in 0..10_001 {
            content.push_str(&secret);
            content.push('\n');
        }
        std::fs::write(project.join("index.js"), content).unwrap();

        let error = match prepare_tarball(
            project,
            &manifest,
            TarballOptions {
                package_json_content: None,
                scan_secrets: true,
            },
        ) {
            Ok(_) => panic!("publish scan must stop at the finding limit"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("10000 finding limit"),
            "unexpected publish scan error: {error}"
        );
    }

    #[test]
    fn target_name_rewrites_preserve_bundled_archive_paths_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let package_root = project.join("node_modules/foo");
        std::fs::create_dir_all(&package_root).unwrap();
        let manifest = serde_json::json!({
            "name": "@lpm.dev/owner.publisher",
            "version": "1.0.0",
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(
            package_root.join("package.json"),
            r#"{"name":"foo","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(package_root.join("index.js"), "portable bundle").unwrap();
        let (tarball, _) = create_tarball(project, &manifest).unwrap();

        for target_name in ["npm-publisher", "@lpm.dev/owner.renamed"] {
            let rewritten =
                rewrite_tarball_name(&tarball, "@lpm.dev/owner.publisher", target_name).unwrap();
            assert_eq!(
                tarball_contents(&rewritten)["package/node_modules/foo/index.js"],
                b"portable bundle"
            );
        }
    }

    #[test]
    fn bundled_dependency_boolean_and_legacy_alias_forms_follow_npm_semantics() {
        let pkg = serde_json::json!({
            "dependencies": {"z": "1", "a": "1"},
            "optionalDependencies": {"optional": "1"},
            "bundledDependencies": true
        });
        assert_eq!(bundled_dependency_names(&pkg).unwrap(), vec!["a", "z"]);
        assert!(
            bundled_dependency_names(&serde_json::json!({
                "dependencies": {"a": "1"},
                "bundledDependencies": false
            }))
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            bundled_dependency_names(&serde_json::json!({
                "bundleDependencies": ["legacy"]
            }))
            .unwrap(),
            vec!["legacy"]
        );
    }

    #[test]
    fn missing_requested_bundle_fails_actionably() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "bundledDependencies": ["missing"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let error = create_tarball(project, &manifest).unwrap_err().to_string();
        assert!(
            error.contains("missing") && error.contains("lpm install"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bundled_dependency_rejects_internal_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let dependency = project.join("node_modules/foo");
        std::fs::create_dir_all(&dependency).unwrap();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dependency.join("package.json"),
            r#"{"name":"foo","version":"1.0.0"}"#,
        )
        .unwrap();
        symlink(project.join("package.json"), dependency.join("leak.json")).unwrap();

        let error = create_tarball(project, &manifest).unwrap_err().to_string();
        assert!(error.contains("unsupported symlink"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn bundled_dependency_rejects_a_project_symlink_to_an_unverified_root() {
        use std::os::unix::fs::symlink;

        let project_dir = tempfile::tempdir().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let project = project_dir.path();
        let outside = outside_dir.path().join("foo");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join("package.json"),
            r#"{"name":"foo","version":"1.0.0"}"#,
        )
        .unwrap();
        symlink(&outside, project.join("node_modules/foo")).unwrap();
        let manifest = serde_json::json!({
            "name": "publisher",
            "version": "1.0.0",
            "bundledDependencies": ["foo"]
        });
        std::fs::write(
            project.join("package.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let error = create_tarball(project, &manifest).unwrap_err().to_string();

        assert!(error.contains("outside the verified"), "{error}");
    }

    #[test]
    fn implicit_publish_reported_paths_match_filtered_archive_entries() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        std::fs::create_dir_all(project.join(".lpm/skills")).unwrap();
        std::fs::create_dir_all(project.join(".lpm/certs")).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();
        std::fs::write(
            project.join(".lpm/skills/package-usage.md"),
            valid_authored_skill(),
        )
        .unwrap();
        std::fs::write(project.join(".lpm/install-hash"), "local install state").unwrap();
        std::fs::write(
            project.join(".lpm/certs/cert.pem"),
            "local development certificate",
        )
        .unwrap();
        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#).unwrap();

        let (data, files) = create_tarball(project, &pkg_json).unwrap();
        let reported_paths = files
            .into_iter()
            .map(|file| file.path)
            .collect::<std::collections::BTreeSet<_>>();
        let expected_paths = [".lpm/skills/package-usage.md", "index.js", "package.json"]
            .into_iter()
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(reported_paths, expected_paths);
        assert_eq!(archive_file_paths(&data), expected_paths);
    }

    #[test]
    fn symlink_excluded_from_tarball() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();

        // Create a symlink that escapes the project
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", project.join("secrets")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/tmp", project.join("linked_dir")).unwrap();

        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/test.pkg", "version": "1.0.0"}"#).unwrap();

        let (_data, files) = create_tarball(project, &pkg_json).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();

        assert!(
            !paths.contains(&"secrets"),
            "symlink to file must be excluded"
        );
        assert!(
            !paths.iter().any(|p| p.starts_with("linked_dir")),
            "symlinked directory must be excluded"
        );
        assert!(paths.contains(&"package.json"));
        assert!(paths.contains(&"index.js"));
    }

    #[test]
    fn is_safe_entry_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        let canonical_root = project.canonicalize().unwrap();

        let regular = project.join("regular.txt");
        std::fs::write(&regular, "hello").unwrap();
        assert!(is_safe_entry(&regular, &canonical_root));

        #[cfg(unix)]
        {
            let symlink = project.join("link.txt");
            std::os::unix::fs::symlink("/etc/passwd", &symlink).unwrap();
            assert!(!is_safe_entry(&symlink, &canonical_root));
        }
    }

    #[test]
    fn npm_tarball_url_scoped() {
        let url = npm_tarball_url("https://registry.npmjs.org", "@scope/name", "1.2.3");
        assert_eq!(
            url,
            "https://registry.npmjs.org/@scope/name/-/name-1.2.3.tgz"
        );
    }

    #[test]
    fn npm_tarball_url_unscoped() {
        let url = npm_tarball_url("https://registry.npmjs.org", "my-package", "0.1.0");
        assert_eq!(
            url,
            "https://registry.npmjs.org/my-package/-/my-package-0.1.0.tgz"
        );
    }

    #[test]
    fn npm_tarball_url_github_packages() {
        let url = npm_tarball_url("https://npm.pkg.github.com", "@owner/pkg", "2.0.0");
        assert_eq!(url, "https://npm.pkg.github.com/@owner/pkg/-/pkg-2.0.0.tgz");
    }

    #[test]
    fn npm_tarball_url_custom_registry() {
        let url = npm_tarball_url("https://npm.corp.com", "my-pkg", "1.0.0");
        assert_eq!(url, "https://npm.corp.com/my-pkg/-/my-pkg-1.0.0.tgz");
    }

    #[test]
    fn npm_tarball_url_trailing_slash() {
        let url = npm_tarball_url("https://registry.npmjs.org/", "@scope/pkg", "1.0.0");
        assert_eq!(url, "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz");
    }

    #[test]
    fn build_npm_payload_strips_lpm_fields() {
        let version_data = serde_json::json!({
            "name": "@scope/pkg",
            "version": "1.0.0",
            "description": "A package",
            "_qualityChecks": [{"id": "readme"}],
            "_qualityMeta": {"score": 80},
            "_npmPackMeta": {"files": []},
            "_lpmConfig": {"ecosystem": "js"},
            "_ecosystem": "js",
            "_swiftManifest": {},
            "dist": {
                "shasum": "abc123",
                "integrity": "sha512-xyz"
            }
        });

        let tarball_data = b"fake tarball";
        let payload = build_npm_payload(
            "https://registry.npmjs.org",
            "@scope/pkg",
            "1.0.0",
            &version_data,
            tarball_data,
            "public",
            NpmPayloadOptions::default(),
        );

        // LPM-specific fields must be stripped from version data
        let ver = &payload["versions"]["1.0.0"];
        assert!(ver.get("_qualityChecks").is_none());
        assert!(ver.get("_qualityMeta").is_none());
        assert!(ver.get("_npmPackMeta").is_none());
        assert!(ver.get("_lpmConfig").is_none());
        assert!(ver.get("_ecosystem").is_none());
        assert!(ver.get("_swiftManifest").is_none());

        // npm fields must be present
        assert_eq!(payload["name"], "@scope/pkg");
        assert_eq!(payload["access"], "public");

        // Attachment content_type must be application/octet-stream (not application/gzip)
        // Key is the full scoped name: @scope/pkg-1.0.0.tgz
        let attachment_key = "@scope/pkg-1.0.0.tgz";
        let attachment = &payload["_attachments"][attachment_key];
        assert_eq!(attachment["content_type"], "application/octet-stream");

        // dist.tarball URL must use the provided registry URL
        let dist = &payload["versions"]["1.0.0"]["dist"];
        assert_eq!(
            dist["tarball"].as_str().unwrap(),
            "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz"
        );
    }

    #[test]
    fn build_npm_payload_uses_github_registry_url() {
        let version_data = serde_json::json!({
            "name": "@owner/pkg",
            "version": "1.0.0",
            "dist": {"shasum": "x", "integrity": "y"}
        });
        let payload = build_npm_payload(
            "https://npm.pkg.github.com",
            "@owner/pkg",
            "1.0.0",
            &version_data,
            b"data",
            "public",
            NpmPayloadOptions::default(),
        );
        let dist = &payload["versions"]["1.0.0"]["dist"];
        assert_eq!(
            dist["tarball"].as_str().unwrap(),
            "https://npm.pkg.github.com/@owner/pkg/-/pkg-1.0.0.tgz"
        );
    }

    #[test]
    fn build_npm_payload_with_tag() {
        let version_data = serde_json::json!({
            "name": "my-pkg",
            "version": "2.0.0-beta.1",
            "dist": {"shasum": "x", "integrity": "y"}
        });

        let payload = build_npm_payload(
            "https://registry.npmjs.org",
            "my-pkg",
            "2.0.0-beta.1",
            &version_data,
            b"data",
            "public",
            NpmPayloadOptions {
                tag: Some("beta"),
                ..Default::default()
            },
        );

        assert_eq!(payload["dist-tags"]["beta"], "2.0.0-beta.1");
    }

    #[test]
    fn build_npm_payload_ignores_untrusted_manifest_provenance_metadata() {
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": "e30=",
                "signatures": []
            },
            "verificationMaterial": {
                "x509CertificateChain": {"certificates": []},
                "tlogEntries": []
            }
        });
        let version_data = serde_json::json!({
            "name": "@scope/pkg",
            "version": "1.0.0",
            "dist": {"shasum": "x", "integrity": "y"},
            "_provenance": bundle,
        });

        let payload = build_npm_payload(
            "https://registry.npmjs.org",
            "@scope/pkg",
            "1.0.0",
            &version_data,
            b"data",
            "public",
            NpmPayloadOptions::default(),
        );

        assert!(
            payload["_attachments"]
                .as_object()
                .expect("attachments must be an object")
                .get("@scope/pkg-1.0.0.sigstore")
                .is_none(),
            "manifest _provenance must not become an npm .sigstore attachment without explicit verification"
        );
    }

    #[test]
    fn build_npm_payload_attaches_explicit_sigstore_bundle() {
        let provenance = NpmProvenanceAttachment {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".into(),
            data: r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.2","checkpoint":"rekor — checkpoint"}"#.into(),
        };
        let version_data = serde_json::json!({
            "name": "@scope/pkg",
            "version": "1.0.0",
            "dist": {"shasum": "x", "integrity": "y"},
        });

        let payload = build_npm_payload(
            "https://registry.npmjs.org",
            "@scope/pkg",
            "1.0.0",
            &version_data,
            b"data",
            "public",
            NpmPayloadOptions {
                provenance_attachment: Some(&provenance),
                ..Default::default()
            },
        );

        let attachment = &payload["_attachments"]["@scope/pkg-1.0.0.sigstore"];
        assert_eq!(
            attachment["content_type"],
            "application/vnd.dev.sigstore.bundle+json;version=0.2",
        );
        assert_eq!(attachment["data"], provenance.data);
        assert_eq!(
            attachment["length"].as_u64().unwrap(),
            javascript_string_length(&provenance.data) as u64
        );
        assert!(
            provenance.data.len() > javascript_string_length(&provenance.data),
            "test fixture must contain non-ASCII so npm string length differs from UTF-8 byte length"
        );
    }

    #[test]
    fn npm_payload_round_trips_through_json() {
        let version_data = serde_json::json!({
            "name": "test",
            "version": "1.0.0",
            "dist": {"shasum": "abc", "integrity": "sha512-def"}
        });

        let payload = build_npm_payload(
            "https://registry.npmjs.org",
            "test",
            "1.0.0",
            &version_data,
            b"tarball",
            "public",
            NpmPayloadOptions::default(),
        );

        // Round-trip through JSON string — no data loss
        let json_str = serde_json::to_string(&payload).unwrap();
        let round_tripped: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(payload, round_tripped);
    }

    #[test]
    fn rewrite_tarball_name_patches_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/neo.multiple", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();

        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/neo.multiple", "version": "1.0.0"}"#)
                .unwrap();

        let (tarball_data, _files) = create_tarball(project, &pkg_json).unwrap();

        // Rewrite to npm name
        let rewritten = rewrite_tarball_name(
            &tarball_data,
            "@lpm.dev/neo.multiple",
            "publish-multiple-registry",
        )
        .unwrap();

        // Extract and check the rewritten tarball
        use std::io::Read;

        let mut decoder = flate2::read::GzDecoder::new(rewritten.as_slice());
        let mut tar_data = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut tar_data).unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == "package/package.json" {
                let mut content = String::new();
                entry.read_to_string(&mut content).unwrap();
                let pkg: serde_json::Value = serde_json::from_str(&content).unwrap();
                assert_eq!(pkg["name"], "publish-multiple-registry");
                return;
            }
        }
        panic!("package/package.json not found in rewritten tarball");
    }

    #[test]
    fn rewrite_tarball_name_noop_when_same() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "same-name", "version": "1.0.0"}"#,
        )
        .unwrap();

        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "same-name", "version": "1.0.0"}"#).unwrap();

        let (tarball_data, _) = create_tarball(project, &pkg_json).unwrap();
        let rewritten = rewrite_tarball_name(&tarball_data, "same-name", "same-name").unwrap();

        // Should return exact same bytes (no rewrite needed)
        assert_eq!(tarball_data, rewritten);
    }

    // ─── Orchestration: tarball rewrite + hash consistency ────────

    #[test]
    fn rewritten_tarball_has_different_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/neo.highlight", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();

        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/neo.highlight", "version": "1.0.0"}"#)
                .unwrap();

        let (original_tarball, _) = create_tarball(project, &pkg_json).unwrap();
        let original_hashes = compute_hashes(&original_tarball);

        // Rewrite to a different name
        let rewritten = rewrite_tarball_name(
            &original_tarball,
            "@lpm.dev/neo.highlight",
            "@tolga/highlight",
        )
        .unwrap();
        let rewritten_hashes = compute_hashes(&rewritten);

        // Hashes must differ because the tarball content changed
        assert_ne!(
            original_hashes.shasum, rewritten_hashes.shasum,
            "shasum must differ after name rewrite"
        );
        assert_ne!(
            original_hashes.integrity, rewritten_hashes.integrity,
            "integrity must differ after name rewrite"
        );
    }

    #[test]
    fn npm_payload_hashes_match_rewritten_tarball() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "@lpm.dev/neo.highlight", "version": "1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();

        let pkg_json: serde_json::Value =
            serde_json::from_str(r#"{"name": "@lpm.dev/neo.highlight", "version": "1.0.0"}"#)
                .unwrap();

        let (original_tarball, _) = create_tarball(project, &pkg_json).unwrap();

        // Rewrite for npm target
        let npm_tarball = rewrite_tarball_name(
            &original_tarball,
            "@lpm.dev/neo.highlight",
            "@tolga/highlight",
        )
        .unwrap();
        let npm_hashes = compute_hashes(&npm_tarball);

        // Build npm payload with the rewritten tarball
        let version_data = serde_json::json!({
            "name": "@tolga/highlight",
            "version": "1.0.0",
            "dist": {"shasum": "stale", "integrity": "stale"}
        });
        let payload = build_npm_payload(
            "https://registry.npmjs.org",
            "@tolga/highlight",
            "1.0.0",
            &version_data,
            &npm_tarball,
            "public",
            NpmPayloadOptions::default(),
        );

        // The payload's dist hashes must match the rewritten tarball, not the stale input
        let dist = &payload["versions"]["1.0.0"]["dist"];
        assert_eq!(
            dist["shasum"].as_str().unwrap(),
            npm_hashes.shasum,
            "payload shasum must match rewritten tarball"
        );
        assert_eq!(
            dist["integrity"].as_str().unwrap(),
            npm_hashes.integrity,
            "payload integrity must match rewritten tarball"
        );
    }

    #[test]
    fn npm_payload_tarball_url_matches_target_registry() {
        let version_data = serde_json::json!({
            "name": "@owner/pkg",
            "version": "1.0.0",
            "dist": {"shasum": "x", "integrity": "y"}
        });

        // Each registry should get its own URL in the payload
        let registries = [
            ("https://registry.npmjs.org", "registry.npmjs.org"),
            ("https://npm.pkg.github.com", "npm.pkg.github.com"),
            ("https://npm.corp.com", "npm.corp.com"),
        ];

        for (url, expected_host) in registries {
            let payload = build_npm_payload(
                url,
                "@owner/pkg",
                "1.0.0",
                &version_data,
                b"data",
                "public",
                NpmPayloadOptions::default(),
            );
            let tarball_url = payload["versions"]["1.0.0"]["dist"]["tarball"]
                .as_str()
                .unwrap();
            assert!(
                tarball_url.contains(expected_host),
                "tarball URL for {url} should contain {expected_host}, got: {tarball_url}"
            );
            assert!(
                !tarball_url.contains("registry.npmjs.org") || url.contains("registry.npmjs.org"),
                "non-npm registry should not contain npmjs.org URL"
            );
        }
    }

    // ─── Workspace dep rewriting in tarball ──────────────────────────

    /// Helper to create a workspace with members for tarball rewrite tests.
    fn make_test_workspace(
        root_dir: &std::path::Path,
        members: Vec<(&str, &str)>,
    ) -> lpm_workspace::Workspace {
        let root_package = lpm_workspace::PackageJson {
            name: Some("root".to_string()),
            version: Some("0.0.0".to_string()),
            workspaces: Some(lpm_workspace::WorkspacesConfig::Globs(
                members.iter().map(|(n, _)| n.to_string()).collect(),
            )),
            ..Default::default()
        };

        let ws_members = members
            .iter()
            .map(|(name, version)| lpm_workspace::WorkspaceMember {
                path: root_dir.join(name),
                package: lpm_workspace::PackageJson {
                    name: Some(name.to_string()),
                    version: Some(version.to_string()),
                    ..Default::default()
                },
            })
            .collect();

        lpm_workspace::Workspace {
            root: root_dir.to_path_buf(),
            root_package,
            members: ws_members,
        }
    }

    #[test]
    fn rewrite_workspace_deps_resolves_protocols() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        // A package that depends on workspace members
        std::fs::write(
            project.join("package.json"),
            r#"{
                "name": "@org/app",
                "version": "1.0.0",
                "dependencies": {
                    "@org/utils": "workspace:*",
                    "@org/core": "workspace:^",
                    "lodash": "^4.0.0"
                }
            }"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();

        let pkg_json: serde_json::Value = serde_json::from_str(
            r#"{"name": "@org/app", "version": "1.0.0", "dependencies": {"@org/utils": "workspace:*", "@org/core": "workspace:^", "lodash": "^4.0.0"}}"#,
        )
        .unwrap();

        let (tarball_data, _) = create_tarball(project, &pkg_json).unwrap();

        // Create workspace with members
        let ws = make_test_workspace(
            project,
            vec![("@org/utils", "2.3.4"), ("@org/core", "1.0.0")],
        );

        let rewritten = rewrite_workspace_deps_in_tarball(&tarball_data, &ws).unwrap();

        // Extract and check
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(rewritten.as_slice());
        let mut tar_data = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut tar_data).unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == "package/package.json" {
                let mut content = String::new();
                entry.read_to_string(&mut content).unwrap();
                let pkg: serde_json::Value = serde_json::from_str(&content).unwrap();
                let deps = pkg["dependencies"].as_object().unwrap();

                assert_eq!(
                    deps["@org/utils"].as_str().unwrap(),
                    "2.3.4",
                    "workspace:* should resolve to exact version"
                );
                assert_eq!(
                    deps["@org/core"].as_str().unwrap(),
                    "^1.0.0",
                    "workspace:^ should resolve to caret range"
                );
                assert_eq!(
                    deps["lodash"].as_str().unwrap(),
                    "^4.0.0",
                    "non-workspace deps should be unchanged"
                );
                return;
            }
        }
        panic!("package/package.json not found in rewritten tarball");
    }

    #[test]
    fn rewrite_workspace_deps_noop_when_no_protocols() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{"name": "plain-pkg", "version": "1.0.0", "dependencies": {"lodash": "^4.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();

        let pkg_json: serde_json::Value = serde_json::from_str(
            r#"{"name": "plain-pkg", "version": "1.0.0", "dependencies": {"lodash": "^4.0.0"}}"#,
        )
        .unwrap();

        let (tarball_data, _) = create_tarball(project, &pkg_json).unwrap();
        let ws = make_test_workspace(project, vec![]);

        let result = rewrite_workspace_deps_in_tarball(&tarball_data, &ws).unwrap();
        assert_eq!(
            tarball_data, result,
            "no workspace: or catalog: deps → tarball should be unchanged"
        );
    }

    #[test]
    fn rewrite_workspace_deps_handles_peer_and_optional() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();

        std::fs::write(
            project.join("package.json"),
            r#"{
                "name": "@org/lib",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.0.0"},
                "peerDependencies": {"@org/core": "workspace:^"},
                "optionalDependencies": {"@org/optional": "workspace:~"}
            }"#,
        )
        .unwrap();
        std::fs::write(project.join("index.js"), "module.exports = {}").unwrap();

        let pkg_json: serde_json::Value = serde_json::from_str(
            r#"{"name": "@org/lib", "version": "1.0.0", "dependencies": {"lodash": "^4.0.0"}, "peerDependencies": {"@org/core": "workspace:^"}, "optionalDependencies": {"@org/optional": "workspace:~"}}"#,
        )
        .unwrap();

        let (tarball_data, _) = create_tarball(project, &pkg_json).unwrap();

        let ws = make_test_workspace(
            project,
            vec![("@org/core", "3.0.0"), ("@org/optional", "1.5.0")],
        );

        let rewritten = rewrite_workspace_deps_in_tarball(&tarball_data, &ws).unwrap();

        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(rewritten.as_slice());
        let mut tar_data = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut tar_data).unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == "package/package.json" {
                let mut content = String::new();
                entry.read_to_string(&mut content).unwrap();
                let pkg: serde_json::Value = serde_json::from_str(&content).unwrap();

                assert_eq!(
                    pkg["peerDependencies"]["@org/core"].as_str().unwrap(),
                    "^3.0.0",
                    "peer workspace:^ should resolve"
                );
                assert_eq!(
                    pkg["optionalDependencies"]["@org/optional"]
                        .as_str()
                        .unwrap(),
                    "~1.5.0",
                    "optional workspace:~ should resolve"
                );
                assert_eq!(
                    pkg["dependencies"]["lodash"].as_str().unwrap(),
                    "^4.0.0",
                    "non-workspace deps unchanged"
                );
                return;
            }
        }
        panic!("package/package.json not found");
    }
}
