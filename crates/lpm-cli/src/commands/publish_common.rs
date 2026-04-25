//! Shared logic for publishing to any registry.
//!
//! Contains tarball creation, file collection, README reading, and hash
//! computation. Used by both `publish.rs` (LPM) and `publish_npm.rs` (npm).

use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// A file entry in the tarball.
#[derive(Debug, Clone)]
pub struct TarballFile {
    pub path: String,
    pub size: u64,
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

    for name in &candidates {
        let path = project_dir.join(name);
        if path.exists()
            && let Ok(content) = std::fs::read_to_string(&path)
        {
            // Cap at 1MB
            let trimmed = if content.len() > 1_000_000 {
                content[..1_000_000].to_string()
            } else {
                content
            };
            return Some(trimmed);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tarball creation
// ---------------------------------------------------------------------------

/// Create a gzipped tarball from the project directory.
///
/// Respects `files` field in package.json if present.
/// Falls back to including everything except common ignores.
/// Rejects symlinks and paths that escape the project directory (S2).
pub fn create_tarball(
    project_dir: &Path,
    pkg_json: &serde_json::Value,
) -> Result<(Vec<u8>, Vec<TarballFile>), LpmError> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let canonical_root = project_dir
        .canonicalize()
        .map_err(|e| LpmError::Registry(format!("cannot canonicalize project directory: {e}")))?;

    let files = collect_package_files(project_dir, pkg_json, &canonical_root)?;
    if files.is_empty() {
        return Err(LpmError::Registry(
            "no files to pack (check package.json 'files' field)".to_string(),
        ));
    }

    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);

        for file in &files {
            let full_path = project_dir.join(&file.path);

            // S2: Symlink escape prevention — double-check before reading.
            // Files were already validated during collection, but a TOCTOU
            // race could replace a regular file with a symlink between
            // collection and reading. Defence in depth.
            if !is_safe_entry(&full_path, &canonical_root) || !full_path.is_file() {
                continue;
            }

            let content = std::fs::read(&full_path)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();

            // npm tarballs have a `package/` prefix
            let tar_path = format!("package/{}", file.path);
            builder
                .append_data(&mut header, &tar_path, &content[..])
                .map_err(LpmError::Io)?;
        }

        builder.finish().map_err(LpmError::Io)?;
    }

    // Gzip compress
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data)?;
    let gzipped = encoder.finish()?;

    Ok((gzipped, files))
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
                eprintln!(
                    "  {} skipping symlink: {}",
                    "⚠".yellow(),
                    path.strip_prefix(canonical_root).unwrap_or(path).display()
                );
                return false;
            }
        }
        Err(e) => {
            eprintln!(
                "  {} skipping {} (cannot read metadata: {e})",
                "⚠".yellow(),
                path.display()
            );
            return false;
        }
    }

    // Verify canonical path is within project directory
    match path.canonicalize() {
        Ok(canonical) => {
            if !canonical.starts_with(canonical_root) {
                eprintln!(
                    "  {} skipping {} (resolves outside project directory)",
                    "⚠".yellow(),
                    path.strip_prefix(canonical_root).unwrap_or(path).display()
                );
                return false;
            }
        }
        Err(e) => {
            eprintln!(
                "  {} skipping {} (cannot canonicalize: {e})",
                "⚠".yellow(),
                path.display()
            );
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
        collect_all_files(project_dir, project_dir, canonical_root, &mut result)?;
    }

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

    // Deduplicate by path
    let mut seen = std::collections::HashSet::new();
    result.retain(|f| seen.insert(f.path.clone()));

    Ok(result)
}

fn collect_dir_files(
    dir: &Path,
    project_root: &Path,
    canonical_root: &Path,
    result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
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

/// Common ignore patterns when no `files` field is specified.
const IGNORE_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "coverage",
    ".nyc_output",
    ".cache",
    "dist",
    ".next",
    ".nuxt",
    "build",
];

const IGNORE_FILES: &[&str] = &[
    ".gitignore",
    ".npmignore",
    ".DS_Store",
    "Thumbs.db",
    ".env",
    ".env.local",
    ".env.live",
];

fn collect_all_files(
    dir: &Path,
    project_root: &Path,
    canonical_root: &Path,
    result: &mut Vec<TarballFile>,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        let path = entry.path();

        if !is_safe_entry(&path, canonical_root) {
            continue;
        }

        if path.is_dir() {
            if IGNORE_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            collect_all_files(&path, project_root, canonical_root, result)?;
        } else if path.is_file() {
            if IGNORE_FILES.contains(&name_str.as_ref()) {
                continue;
            }
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
pub fn rewrite_tarball_name(
    tarball_data: &[u8],
    original_name: &str,
    target_name: &str,
) -> Result<Vec<u8>, LpmError> {
    if original_name == target_name {
        return Ok(tarball_data.to_vec());
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

            // Patch package.json at the root of the tarball (package/package.json)
            if path == "package/package.json"
                && let Ok(mut pkg) = serde_json::from_slice::<serde_json::Value>(&content)
            {
                pkg["name"] = serde_json::json!(target_name);
                content = serde_json::to_vec_pretty(&pkg).unwrap_or(content);
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

/// Rewrite `workspace:` and `catalog:` protocol references in the tarball's `package.json`.
///
/// Monorepo packages use `"workspace:*"`, `"workspace:^"`, etc. in their
/// dependencies. These are only valid locally — registries (npm, LPM, GitHub)
/// reject or can't resolve them. This function resolves workspace/catalog
/// protocols to concrete semver ranges before the tarball is published.
///
/// Must be called BEFORE hash computation and provenance generation.
/// Returns the original tarball unchanged if no protocols are found.
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

    // Check if rewriting is needed
    let needs_rewrite = {
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let mut found = false;
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
                let content_str = String::from_utf8_lossy(&content);
                found = content_str.contains("\"workspace:") || content_str.contains("\"catalog:");
                break;
            }
        }
        found
    };

    if !needs_rewrite {
        return Ok(tarball_data.to_vec());
    }

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

            if path == "package/package.json"
                && let Ok(mut pkg) = serde_json::from_slice::<serde_json::Value>(&content)
            {
                let dep_fields = [
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                    "optionalDependencies",
                ];

                for field in &dep_fields {
                    if let Some(deps_obj) = pkg.get(field).and_then(|v| v.as_object()).cloned() {
                        let mut resolved_deps: serde_json::Map<String, serde_json::Value> =
                            serde_json::Map::new();
                        let mut deps_map: std::collections::HashMap<String, String> = deps_obj
                            .iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("*").to_string()))
                            .collect();

                        // Resolve workspace: protocol
                        if let Err(e) =
                            lpm_workspace::resolve_workspace_protocol(&mut deps_map, workspace)
                        {
                            return Err(LpmError::Registry(format!(
                                "failed to resolve workspace: protocol in {field}: {e}"
                            )));
                        }

                        // Resolve catalog: protocol
                        if !workspace.root_package.catalogs.is_empty()
                            && let Err(e) = lpm_workspace::resolve_catalog_protocol(
                                &mut deps_map,
                                &workspace.root_package.catalogs,
                            )
                        {
                            return Err(LpmError::Registry(format!(
                                "failed to resolve catalog: protocol in {field}: {e}"
                            )));
                        }

                        for (k, v) in &deps_map {
                            resolved_deps.insert(k.clone(), serde_json::Value::String(v.clone()));
                        }
                        pkg[field] = serde_json::Value::Object(resolved_deps);
                    }
                }

                content = serde_json::to_vec_pretty(&pkg).unwrap_or(content);
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

/// Build the npm-compatible publish payload.
///
/// Takes the LPM version_data, strips LPM-specific fields, sets npm-required
/// fields, and returns a JSON value ready for PUT to the target registry.
pub fn build_npm_payload(
    registry_url: &str,
    npm_name: &str,
    version: &str,
    version_data: &serde_json::Value,
    tarball_data: &[u8],
    access: &str,
    tag: Option<&str>,
) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

    let dist_tag = tag.unwrap_or("latest");

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
        "_attachments": {
            tarball_key: {
                "content_type": "application/octet-stream",
                "data": tarball_base64,
                "length": tarball_data.len(),
            }
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            None,
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
            None,
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
            Some("beta"),
        );

        assert_eq!(payload["dist-tags"]["beta"], "2.0.0-beta.1");
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
            None,
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
            None,
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
                None,
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
        use std::collections::HashMap;

        let root_package = lpm_workspace::PackageJson {
            name: Some("root".to_string()),
            version: Some("0.0.0".to_string()),
            dependencies: HashMap::new(),
            dev_dependencies: HashMap::new(),
            peer_dependencies: HashMap::new(),
            optional_dependencies: HashMap::new(),
            overrides: HashMap::new(),
            resolutions: HashMap::new(),
            workspaces: Some(lpm_workspace::WorkspacesConfig::Globs(
                members.iter().map(|(n, _)| n.to_string()).collect(),
            )),
            lpm: None,
            engines: HashMap::new(),
            scripts: HashMap::new(),
            bin: None,
            catalogs: HashMap::new(),
        };

        let ws_members = members
            .iter()
            .map(|(name, version)| lpm_workspace::WorkspaceMember {
                path: root_dir.join(name),
                package: lpm_workspace::PackageJson {
                    name: Some(name.to_string()),
                    version: Some(version.to_string()),
                    dependencies: HashMap::new(),
                    dev_dependencies: HashMap::new(),
                    peer_dependencies: HashMap::new(),
                    optional_dependencies: HashMap::new(),
                    overrides: HashMap::new(),
                    resolutions: HashMap::new(),
                    workspaces: None,
                    lpm: None,
                    engines: HashMap::new(),
                    scripts: HashMap::new(),
                    bin: None,
                    catalogs: HashMap::new(),
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
