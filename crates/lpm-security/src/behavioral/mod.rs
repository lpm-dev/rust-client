//! Client-side behavioral analysis for all packages (npm + @lpm.dev).
//!
//! Detects 23 security-relevant tags across three groups:
//! - **Source tags** (10): API usage patterns (filesystem, network, eval, etc.)
//! - **Supply chain tags** (8): Obfuscation confidence, entropy, minified, telemetry, etc.
//! - **Manifest tags** (5): License + dependency configuration issues
//!
//! Runs on every extracted package in the store. Results are cached in
//! `.lpm-security.json` alongside the package — computed once per version, forever.
//!
//! ## Security
//!
//! All regex patterns use the `regex` crate which guarantees linear-time matching
//! (Thompson NFA). NEVER use `fancy-regex` here — we scan untrusted input from
//! arbitrary npm packages.
//!
//! ## Performance
//!
//! - `RegexSet` + `OnceLock` for compile-once, single-pass matching
//! - File extension filtering before I/O (skip non-source files)
//! - Per-file size limit: 2MB (skip bundled/generated files)
//! - Per-package total limit: 50MB scanned
//! - Shannon entropy pre-filter: 95% of files skip the expensive extraction
//! - Comment stripping: streaming state machine, preserves newlines
//!
//! Target: < 100ms per typical 100-file package on M1.

pub mod manifest;
pub mod secrets;
pub mod source;
pub mod supply_chain;

use manifest::ManifestTags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use source::SourceTags;
use std::collections::{BinaryHeap, HashMap};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use supply_chain::SupplyChainTags;

/// Current schema version for `.lpm-security.json`.
/// Bump this when adding new tags or changing tag semantics — cached
/// files with older versions will be automatically re-analyzed.
pub const SCHEMA_VERSION: u32 = 5;

/// Maximum file size to scan (2MB). Files larger than this are skipped.
/// No legitimate single source file is this large — it's bundled/generated.
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

/// Maximum total bytes to scan per package (50MB). Analysis aborts (with warning)
/// if cumulative reads exceed this, returning partial results.
const MAX_TOTAL_SCAN_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum number of source files to scan per package.
const MAX_FILES_PER_PACKAGE: usize = 5_000;

/// Bytes sampled from both the head and tail of oversized source files.
const OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES: usize = 128 * 1024;

/// Maximum oversized source file evidence records persisted in metadata.
const MAX_OVERSIZED_SOURCE_FILE_EVIDENCE: usize = 20;

/// Source file extensions that should be scanned.
const SOURCE_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx"];

/// Complete analysis result for a single package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageAnalysis {
    /// Schema version — re-analyze if this doesn't match SCHEMA_VERSION.
    pub version: u32,
    /// ISO 8601 timestamp of when analysis was performed.
    pub analyzed_at: String,
    /// Source code behavioral tags (10).
    pub source: SourceTags,
    /// Supply chain & code quality tags (8).
    pub supply_chain: SupplyChainTags,
    /// Package manifest tags (5).
    pub manifest: ManifestTags,
    /// Additional metadata (file count, URL domains, etc.)
    pub meta: AnalysisMeta,
}

/// Metadata about the analysis run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisMeta {
    /// Number of source files scanned.
    #[serde(default)]
    pub files_scanned: usize,
    /// Total bytes of source code scanned.
    #[serde(default)]
    pub bytes_scanned: u64,
    /// Whether any limit was reached during analysis.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub limit_reached: bool,
    /// Unique URL domains found in source code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_domains: Vec<String>,
    /// Oversized source files that exceeded the full scan ceiling and were sampled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oversized_source_files: Vec<OversizedSourceFileEvidence>,
}

/// Compact evidence for a source file that exceeded the full scan limit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OversizedSourceFileEvidence {
    pub path: String,
    pub size_bytes: u64,
    pub sample_bytes_scanned: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub minified_filename: bool,
}

/// Analyze a package directory for behavioral tags.
///
/// Walks the directory, filters by file extension, reads source files,
/// strips comments, and runs all tag detectors. Returns a complete
/// `PackageAnalysis` that can be serialized to `.lpm-security.json`.
///
/// Respects per-file (2MB) and per-package (50MB) size limits.
/// Skips `.min.js` files for source tag analysis (but flags `minified: true`).
pub fn analyze_package(package_dir: &Path) -> PackageAnalysis {
    analyze_package_with_timings(package_dir).0
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Timing attribution produced alongside a package analysis.
pub struct PackageAnalysisTimings {
    /// Nanoseconds spent discovering and scanning source files.
    pub source_scan_ns: u128,
}

/// Analyze a package and return source-scan timing attribution.
pub fn analyze_package_with_timings(
    package_dir: &Path,
) -> (PackageAnalysis, PackageAnalysisTimings) {
    let source_scan_start = std::time::Instant::now();
    // Walk source files
    let source_files = collect_source_files(package_dir);

    // Use rayon for parallel scanning on packages with many files (20+).
    // Smaller packages don't benefit from thread pool overhead.
    let file_result = if source_files.len() >= 20 {
        analyze_files_parallel(package_dir, &source_files)
    } else {
        analyze_files_sequential(package_dir, &source_files)
    };
    let source_scan_ns = source_scan_start.elapsed().as_nanos();

    // Set trivial tag at package level (< 10 lines across ALL source files)
    let mut supply_chain_tags = file_result.supply_chain;
    if file_result.meta.files_scanned > 0 {
        supply_chain_tags.trivial =
            file_result.total_code_lines < 10 && file_result.total_export_count <= 1;
    }

    // Deduplicate URL domains
    let mut url_domains = file_result.url_domains;
    url_domains.sort_unstable();
    url_domains.dedup();
    let mut meta = file_result.meta;
    meta.url_domains = url_domains;

    // Manifest tags (5) — read package.json
    let manifest_tags = analyze_package_manifest(package_dir);

    // Build timestamp
    let analyzed_at = chrono::Utc::now().to_rfc3339();

    (
        PackageAnalysis {
            version: SCHEMA_VERSION,
            analyzed_at,
            source: file_result.source,
            supply_chain: supply_chain_tags,
            manifest: manifest_tags,
            meta,
        },
        PackageAnalysisTimings { source_scan_ns },
    )
}

/// Analyze a package through an already-open directory capability.
///
/// The descriptor pins the selected package root. Every nested directory and
/// file is opened without following links, so concurrent path replacement
/// cannot redirect the scan outside that root.
pub fn analyze_package_from_open_dir(package_dir: &cap_std::fs::Dir) -> PackageAnalysis {
    analyze_package_from_open_dir_with_fingerprint(package_dir).0
}

/// Analyze a descriptor-rooted package and fingerprint the exact bytes used.
///
/// The fingerprint is unavailable when discovery or any selected input read
/// fails. The returned partial analysis remains usable for the current
/// command, but callers must not persist it for later reuse.
pub fn analyze_package_from_open_dir_with_fingerprint(
    package_dir: &cap_std::fs::Dir,
) -> (PackageAnalysis, Option<String>) {
    let mut source_files = CapSourceFiles::new();
    let mut discovery_limit_reached = false;
    let discovery_complete = collect_cap_fingerprint_files(
        package_dir,
        Path::new(""),
        &mut source_files,
        &mut discovery_limit_reached,
    )
    .is_ok();
    let source_files = source_files.into_sorted_vec();
    let (source_files, prefix_limit_reached) = cap_scan_prefix(&source_files);
    let (mut file_result, mut fingerprint, runtime_limit_reached) =
        analyze_cap_files_with_fingerprint(package_dir, source_files, discovery_complete);
    file_result.meta.limit_reached |=
        discovery_limit_reached || prefix_limit_reached || runtime_limit_reached;
    let mut supply_chain_tags = file_result.supply_chain;
    if file_result.meta.files_scanned > 0 {
        supply_chain_tags.trivial =
            file_result.total_code_lines < 10 && file_result.total_export_count <= 1;
    }
    let mut url_domains = file_result.url_domains;
    url_domains.sort_unstable();
    url_domains.dedup();
    let mut meta = file_result.meta;
    meta.url_domains = url_domains;

    let manifest_tags = match read_package_manifest_from_open_dir(package_dir) {
        Ok(Some((size, content))) => {
            if let Some(hasher) = fingerprint.as_mut() {
                hash_fingerprint_record_digest(
                    hasher,
                    b"package.json",
                    size,
                    content.len() as u64,
                    Sha256::digest(&content).into(),
                );
            }
            analyze_package_manifest_bytes(&content)
        }
        Ok(None) => {
            if let Some(hasher) = fingerprint.as_mut() {
                hasher.update(b"package.json\0missing\0");
            }
            ManifestTags::default()
        }
        Err(_) => {
            fingerprint = None;
            ManifestTags::default()
        }
    };
    let analysis = PackageAnalysis {
        version: SCHEMA_VERSION,
        analyzed_at: chrono::Utc::now().to_rfc3339(),
        source: file_result.source,
        supply_chain: supply_chain_tags,
        manifest: manifest_tags,
        meta,
    };
    let fingerprint = fingerprint.map(|mut hasher| {
        hasher.update(b"limits\0");
        hasher.update([u8::from(
            discovery_limit_reached || prefix_limit_reached || runtime_limit_reached,
        )]);
        format!("sha256-{:x}", hasher.finalize())
    });
    (analysis, fingerprint)
}

/// Hash the exact package inputs that can affect behavioral analysis.
///
/// The walk uses the same path, file-count, file-size, and total-byte policy as
/// [`analyze_package_from_open_dir`]. Symlinks and ignored paths do not
/// participate because the analyzer does not read them. Any unexpected I/O
/// error prevents cache reuse instead of authenticating a partial snapshot.
pub fn package_input_fingerprint_from_open_dir(
    package_dir: &cap_std::fs::Dir,
) -> std::io::Result<String> {
    let mut files = CapSourceFiles::new();
    let mut discovery_limit_reached = false;
    collect_cap_fingerprint_files(
        package_dir,
        Path::new(""),
        &mut files,
        &mut discovery_limit_reached,
    )?;
    let files = files.into_sorted_vec();
    let (files, total_limit_reached) = cap_scan_prefix(&files);

    let mut hasher = new_fingerprint_hasher();
    let mut planned_bytes = 0u64;
    let mut runtime_limit_reached = false;
    for source_file in files {
        let (file, size) = open_cap_source_file(package_dir, &source_file.path)?;
        let file_bytes = planned_scan_bytes(size);
        if planned_bytes.saturating_add(file_bytes) > MAX_TOTAL_SCAN_BYTES {
            runtime_limit_reached = true;
            break;
        }
        planned_bytes += file_bytes;
        let (bytes_read, content_digest) = digest_cap_source_file(file, size)?;
        hash_fingerprint_record_digest(
            &mut hasher,
            source_file.path.as_os_str().as_encoded_bytes(),
            size,
            bytes_read,
            content_digest,
        );
    }

    match digest_package_manifest_from_open_dir(package_dir)? {
        Some((size, bytes_read, digest)) => {
            hash_fingerprint_record_digest(&mut hasher, b"package.json", size, bytes_read, digest)
        }
        None => hasher.update(b"package.json\0missing\0"),
    }

    hasher.update(b"limits\0");
    hasher.update([u8::from(
        discovery_limit_reached || total_limit_reached || runtime_limit_reached,
    )]);

    Ok(format!("sha256-{:x}", hasher.finalize()))
}

fn new_fingerprint_hasher() -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"lpm-behavioral-input-v2\0");
    hasher.update(SCHEMA_VERSION.to_le_bytes());
    hasher
}

fn collect_cap_fingerprint_files(
    directory: &cap_std::fs::Dir,
    relative_dir: &Path,
    files: &mut CapSourceFiles,
    limit_reached: &mut bool,
) -> std::io::Result<()> {
    use cap_fs_ext::DirExt as _;

    for entry in directory.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let relative = relative_dir.join(&name);
        let metadata = directory.symlink_metadata(&name)?;
        if metadata.is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            if !PackageAnalyzer::should_scan_directory(&relative) {
                continue;
            }
            let child = directory.open_dir_nofollow(&name)?;
            collect_cap_fingerprint_files(&child, &relative, files, limit_reached)?;
        } else if metadata.is_file() && PackageAnalyzer::should_scan(&relative, metadata.len()) {
            let candidate = CapSourceFile {
                path: relative,
                size: metadata.len(),
            };
            *limit_reached |= files.insert(candidate);
        }
    }
    Ok(())
}

fn hash_fingerprint_record_digest(
    hasher: &mut Sha256,
    path: &[u8],
    size: u64,
    bytes_read: u64,
    content_digest: [u8; 32],
) {
    hasher.update((path.len() as u64).to_le_bytes());
    hasher.update(path);
    hasher.update(size.to_le_bytes());
    hasher.update(bytes_read.to_le_bytes());
    hasher.update(content_digest);
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CapSourceFile {
    path: std::path::PathBuf,
    size: u64,
}

enum CapSourceFiles {
    Collecting(Vec<CapSourceFile>),
    Limited(BinaryHeap<CapSourceFile>),
}

impl CapSourceFiles {
    fn new() -> Self {
        Self::Collecting(Vec::new())
    }

    fn insert(&mut self, candidate: CapSourceFile) -> bool {
        match self {
            Self::Collecting(files) if files.len() < MAX_FILES_PER_PACKAGE => {
                files.push(candidate);
                false
            }
            Self::Collecting(files) => {
                let mut collected = std::mem::take(files);
                collected.shrink_to_fit();
                let mut limited = BinaryHeap::from(collected);
                if limited.peek().is_some_and(|largest| candidate < *largest) {
                    limited.pop();
                    limited.push(candidate);
                }
                *self = Self::Limited(limited);
                true
            }
            Self::Limited(files) => {
                if files.peek().is_some_and(|largest| candidate < *largest) {
                    files.pop();
                    files.push(candidate);
                }
                true
            }
        }
    }

    fn into_sorted_vec(self) -> Vec<CapSourceFile> {
        match self {
            Self::Collecting(mut files) => {
                files.sort_unstable();
                files
            }
            Self::Limited(files) => files.into_sorted_vec(),
        }
    }
}

fn cap_scan_prefix(files: &[CapSourceFile]) -> (&[CapSourceFile], bool) {
    let mut planned_bytes = 0u64;
    for (index, file) in files.iter().enumerate() {
        let file_bytes = planned_scan_bytes(file.size);
        if planned_bytes.saturating_add(file_bytes) > MAX_TOTAL_SCAN_BYTES {
            return (&files[..index], true);
        }
        planned_bytes += file_bytes;
    }
    (files, false)
}

fn planned_scan_bytes(size: u64) -> u64 {
    if size <= MAX_FILE_SIZE {
        return size;
    }
    let chunk = (OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES as u64).min(size);
    if size.saturating_sub(chunk) > chunk {
        chunk.saturating_mul(2).saturating_add(1)
    } else {
        chunk
    }
}

fn open_cap_source_file(
    root: &cap_std::fs::Dir,
    relative_path: &Path,
) -> std::io::Result<(cap_std::fs::File, u64)> {
    use cap_fs_ext::{
        DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _,
    };

    let mut parent = root.try_clone()?;
    let mut components = relative_path.components().peekable();
    let mut leaf = None;
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "source path contains an unsafe component",
            ));
        };
        if components.peek().is_some() {
            parent = parent.open_dir_nofollow(name)?;
        } else {
            leaf = Some(name.to_os_string());
        }
    }
    let leaf = leaf.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source path has no file name",
        )
    })?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = parent.open_with(&leaf, &options)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.is_symlink() {
        return Err(std::io::Error::other(
            "source path is not a safe regular file",
        ));
    }
    Ok((file, metadata.len()))
}

struct OpenCapSourceFile {
    path: std::path::PathBuf,
    file: cap_std::fs::File,
    size: u64,
}

struct ScannedCapSourceFile {
    path: std::path::PathBuf,
    size: u64,
    bytes_read: u64,
    content_digest: [u8; 32],
    analysis: Option<FileAnalysisResult>,
}

fn analyze_open_cap_source_file(
    source_file: OpenCapSourceFile,
    comment_buf: &mut Vec<u8>,
) -> std::io::Result<ScannedCapSourceFile> {
    let mut file = source_file.file.into_std();
    let bytes = if source_file.size > MAX_FILE_SIZE {
        read_oversized_source_sample_from_open_file(&mut file, source_file.size)?
    } else {
        lpm_common::read_file_capped_from_open_file(file, &source_file.path, MAX_FILE_SIZE)
            .map_err(std::io::Error::other)?
            .0
    };
    let analysis = source_file
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|filename| {
            if source_file.size > MAX_FILE_SIZE {
                analyze_oversized_source_sample(
                    &source_file.path,
                    source_file.size,
                    &bytes,
                    comment_buf,
                )
            } else {
                analyze_bytes_with_scratch(filename, &bytes, comment_buf)
            }
        });
    Ok(ScannedCapSourceFile {
        path: source_file.path,
        size: source_file.size,
        bytes_read: bytes.len() as u64,
        content_digest: Sha256::digest(&bytes).into(),
        analysis,
    })
}

fn analyze_cap_files_with_fingerprint(
    package_dir: &cap_std::fs::Dir,
    files: &[CapSourceFile],
    fingerprint_valid: bool,
) -> (AccumulatedResult, Option<Sha256>, bool) {
    use rayon::prelude::*;

    let mut source_tags = SourceTags::default();
    let mut supply_chain_tags = SupplyChainTags::default();
    let mut meta = AnalysisMeta::default();
    let mut all_url_domains = Vec::new();
    let mut total_code_lines = 0usize;
    let mut total_export_count = 0usize;
    let mut fingerprint = fingerprint_valid.then(new_fingerprint_hasher);
    let mut planned_bytes = 0u64;
    let mut actual_bytes = 0u64;
    let mut runtime_limit_reached = false;
    let batch_size = if files.len() >= 20 {
        rayon::current_num_threads()
            .saturating_mul(2)
            .clamp(20, 128)
    } else {
        files.len().max(1)
    };

    'batches: for batch in files.chunks(batch_size) {
        let mut opened = Vec::with_capacity(batch.len());
        for source_file in batch {
            let (file, size) = match open_cap_source_file(package_dir, &source_file.path) {
                Ok(opened) => opened,
                Err(_) => {
                    fingerprint = None;
                    continue;
                }
            };
            let file_bytes = planned_scan_bytes(size);
            if planned_bytes.saturating_add(file_bytes) > MAX_TOTAL_SCAN_BYTES {
                runtime_limit_reached = true;
                break;
            }
            planned_bytes += file_bytes;
            opened.push(OpenCapSourceFile {
                path: source_file.path.clone(),
                file,
                size,
            });
        }

        let results: Vec<std::io::Result<ScannedCapSourceFile>> = if opened.len() >= 20 {
            opened
                .into_par_iter()
                .map_init(Vec::new, |comment_buf, source_file| {
                    analyze_open_cap_source_file(source_file, comment_buf)
                })
                .collect()
        } else {
            let mut comment_buf = Vec::new();
            opened
                .into_iter()
                .map(|source_file| analyze_open_cap_source_file(source_file, &mut comment_buf))
                .collect()
        };

        for scanned in results {
            let scanned = match scanned {
                Ok(scanned) => scanned,
                Err(_) => {
                    fingerprint = None;
                    continue;
                }
            };
            if actual_bytes.saturating_add(scanned.bytes_read) > MAX_TOTAL_SCAN_BYTES {
                runtime_limit_reached = true;
                break 'batches;
            }
            actual_bytes += scanned.bytes_read;
            if let Some(hasher) = fingerprint.as_mut() {
                hash_fingerprint_record_digest(
                    hasher,
                    scanned.path.as_os_str().as_encoded_bytes(),
                    scanned.size,
                    scanned.bytes_read,
                    scanned.content_digest,
                );
            }
            if let Some(result) = scanned.analysis {
                accumulate_result(
                    &mut source_tags,
                    &mut supply_chain_tags,
                    &mut all_url_domains,
                    &mut total_code_lines,
                    &mut total_export_count,
                    &mut meta,
                    result,
                );
            }
        }
        if runtime_limit_reached {
            break;
        }
    }
    meta.limit_reached |= runtime_limit_reached;
    (
        AccumulatedResult {
            source: source_tags,
            supply_chain: supply_chain_tags,
            url_domains: all_url_domains,
            total_code_lines,
            total_export_count,
            meta,
        },
        fingerprint,
        runtime_limit_reached,
    )
}

fn digest_cap_source_file(file: cap_std::fs::File, size: u64) -> std::io::Result<(u64, [u8; 32])> {
    if size > MAX_FILE_SIZE {
        let mut file = file.into_std();
        let sample = read_oversized_source_sample_from_open_file(&mut file, size)?;
        return Ok((sample.len() as u64, Sha256::digest(&sample).into()));
    }

    let mut file = file.into_std().take(MAX_FILE_SIZE.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes_read = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        if bytes_read > MAX_FILE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "source file grew beyond the scan limit while fingerprinting",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((bytes_read, hasher.finalize().into()))
}

fn digest_package_manifest_from_open_dir(
    package_dir: &cap_std::fs::Dir,
) -> std::io::Result<Option<(u64, u64, [u8; 32])>> {
    let (file, size) = match open_cap_source_file(package_dir, Path::new("package.json")) {
        Ok(opened) => opened,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let limit = lpm_common::CONFIG_FILE_SIZE_CAP_BYTES;
    if size > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package.json exceeds the configuration file size limit",
        ));
    }
    let mut file = file.into_std().take(limit.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes_read = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        if bytes_read > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "package.json grew beyond the configuration file size limit",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Some((size, bytes_read, hasher.finalize().into())))
}

fn read_package_manifest_from_open_dir(
    package_dir: &cap_std::fs::Dir,
) -> std::io::Result<Option<(u64, Vec<u8>)>> {
    let (file, size) = match open_cap_source_file(package_dir, Path::new("package.json")) {
        Ok(opened) => opened,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let content = lpm_common::read_file_capped_from_open_file(
        file.into_std(),
        Path::new("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .map_err(std::io::Error::other)?
    .0;
    Ok(Some((size, content)))
}

/// Intermediate result from scanning a single file. Public so the
/// streaming path in lpm-store can feed per-entry bytes into
/// [`analyze_bytes`] and merge results without reopening [`PackageAnalyzer`].
#[derive(Debug, Default)]
pub struct FileAnalysisResult {
    pub source: SourceTags,
    pub supply_chain: SupplyChainTags,
    pub url_domains: Vec<String>,
    pub total_code_lines: usize,
    pub total_export_count: usize,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub oversized_source_files: Vec<OversizedSourceFileEvidence>,
}

/// Accumulated result from scanning all files.
struct AccumulatedResult {
    source: SourceTags,
    supply_chain: SupplyChainTags,
    url_domains: Vec<String>,
    total_code_lines: usize,
    total_export_count: usize,
    meta: AnalysisMeta,
}

/// Analyze a single file. Returns None if the file should be skipped.
fn analyze_single_file(
    package_dir: &Path,
    file_path: &std::path::PathBuf,
    comment_buf: &mut Vec<u8>,
) -> Option<FileAnalysisResult> {
    let file_size = std::fs::metadata(file_path).ok()?.len();
    let filename = file_path.file_name()?.to_str()?.to_string();
    let relative_path = file_path
        .strip_prefix(package_dir)
        .unwrap_or(file_path.as_path());

    if file_size > MAX_FILE_SIZE {
        return Some(analyze_oversized_source_file(
            relative_path,
            file_path,
            file_size,
            comment_buf,
        ));
    }

    let raw_content = std::fs::read(file_path).ok()?;
    Some(analyze_bytes_with_scratch(
        &filename,
        &raw_content,
        comment_buf,
    ))
}

/// Core scan pass without the filesystem read — takes the file's name and
/// raw bytes and returns the same `FileAnalysisResult` as
/// [`analyze_single_file`]. The fused-scan path in `lpm-store` invokes this
/// during tar extraction, using bytes the extractor already had in hand
/// instead of re-reading the file a second time.
///
/// The caller is responsible for:
/// - filtering by extension (`SOURCE_EXTENSIONS`), `.d.ts`/`.map`
///   exclusion, and directory filtering (`node_modules` / `__tests__` /
///   `test`). [`PackageAnalyzer::should_scan`] encodes the current policy.
/// - routing files over the 2 MB full-scan limit to
///   [`PackageAnalyzer::feed_oversized_source_file`] or another bounded
///   sampling path instead of passing the entire file here.
///
/// Pure function: no I/O, no allocations beyond the comment-stripped
/// scratch buffer. Safe to call from any thread, no runtime needed.
pub fn analyze_bytes(filename: &str, raw_content: &[u8]) -> FileAnalysisResult {
    let mut comment_buf = Vec::new();
    analyze_bytes_with_scratch(filename, raw_content, &mut comment_buf)
}

fn analyze_bytes_with_scratch(
    filename: &str,
    raw_content: &[u8],
    comment_buf: &mut Vec<u8>,
) -> FileAnalysisResult {
    source::strip_comments(raw_content, comment_buf);
    let stripped = String::from_utf8_lossy(comment_buf.as_slice());

    let file_source_tags = source::analyze_source(&stripped);
    let domains = supply_chain::extract_url_domains(&stripped);
    let mut file_supply_tags = supply_chain::analyze_supply_chain_with_url_presence(
        &stripped,
        raw_content,
        !domains.is_empty(),
    );
    file_supply_tags.minified |= supply_chain::is_minified_filename(filename);
    let trivial = supply_chain::analyze_trivial(&stripped);

    FileAnalysisResult {
        source: file_source_tags,
        supply_chain: file_supply_tags,
        url_domains: domains,
        total_code_lines: trivial.total_code_lines,
        total_export_count: trivial.export_count,
        files_scanned: 1,
        bytes_scanned: raw_content.len() as u64,
        oversized_source_files: Vec::new(),
    }
}

fn analyze_oversized_source_file(
    relative_path: &Path,
    file_path: &Path,
    size: u64,
    comment_buf: &mut Vec<u8>,
) -> FileAnalysisResult {
    let sample = read_oversized_source_sample(file_path, size).unwrap_or_default();
    analyze_oversized_source_sample(relative_path, size, &sample, comment_buf)
}

fn analyze_oversized_source_sample(
    relative_path: &Path,
    size: u64,
    sample: &[u8],
    comment_buf: &mut Vec<u8>,
) -> FileAnalysisResult {
    let filename = relative_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let mut result = if sample.is_empty() {
        FileAnalysisResult::default()
    } else {
        analyze_bytes_with_scratch(filename, sample, comment_buf)
    };

    result.files_scanned = 0;
    result.bytes_scanned = sample.len() as u64;
    result.supply_chain.minified |= supply_chain::is_minified_filename(filename);

    let evidence = OversizedSourceFileEvidence {
        path: path_to_slash(relative_path),
        size_bytes: size,
        sample_bytes_scanned: sample.len() as u64,
        signals: oversized_source_signals(&result.source, &result.supply_chain),
        url_domains: result.url_domains.clone(),
        minified_filename: supply_chain::is_minified_filename(filename),
    };
    result.oversized_source_files = vec![evidence];
    result
}

fn read_oversized_source_sample(file_path: &Path, size: u64) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(file_path)?;
    read_oversized_source_sample_from_open_file(&mut file, size)
}

fn read_oversized_source_sample_from_open_file(
    file: &mut std::fs::File,
    size: u64,
) -> std::io::Result<Vec<u8>> {
    let chunk = OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES.min(size as usize);
    let mut sample = Vec::with_capacity(chunk.saturating_mul(2).saturating_add(1));

    read_file_chunk(file, 0, chunk, &mut sample)?;

    let tail_start = size.saturating_sub(chunk as u64);
    if tail_start > chunk as u64 {
        sample.push(b'\n');
        read_file_chunk(file, tail_start, chunk, &mut sample)?;
    }

    Ok(sample)
}

fn read_file_chunk(
    file: &mut std::fs::File,
    start: u64,
    max_bytes: usize,
    out: &mut Vec<u8>,
) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(start))?;
    let mut limited = file.by_ref().take(max_bytes as u64);
    limited.read_to_end(out)?;
    Ok(())
}

fn oversized_source_sample_from_bytes(bytes: &[u8]) -> Vec<u8> {
    let chunk = OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES.min(bytes.len());
    let tail_start = bytes.len().saturating_sub(chunk);
    let mut sample = Vec::with_capacity(chunk.saturating_mul(2).saturating_add(1));
    sample.extend_from_slice(&bytes[..chunk]);
    if tail_start > chunk {
        sample.push(b'\n');
        sample.extend_from_slice(&bytes[tail_start..]);
    }
    sample
}

/// Build the "oversized minified" result without reading file bytes.
fn oversized_minified_result(relative_path: &Path, size: u64) -> FileAnalysisResult {
    let mut result = FileAnalysisResult {
        oversized_source_files: vec![OversizedSourceFileEvidence {
            path: path_to_slash(relative_path),
            size_bytes: size,
            sample_bytes_scanned: 0,
            signals: vec!["minified".to_string()],
            url_domains: Vec::new(),
            minified_filename: true,
        }],
        ..Default::default()
    };
    result.supply_chain.minified = true;
    result
}

fn oversized_source_signals(source: &SourceTags, supply_chain: &SupplyChainTags) -> Vec<String> {
    let mut signals = Vec::new();
    push_signal(&mut signals, source.filesystem, "filesystem");
    push_signal(&mut signals, source.network, "network");
    push_signal(&mut signals, source.child_process, "childProcess");
    push_signal(&mut signals, source.environment_vars, "environmentVars");
    push_signal(&mut signals, source.eval, "eval");
    push_signal(&mut signals, source.native_bindings, "nativeBindings");
    push_signal(&mut signals, source.crypto, "crypto");
    push_signal(&mut signals, source.shell, "shell");
    push_signal(&mut signals, source.web_socket, "webSocket");
    push_signal(&mut signals, source.dynamic_require, "dynamicRequire");
    push_signal(&mut signals, supply_chain.obfuscated, "obfuscated");
    push_signal(
        &mut signals,
        supply_chain.possible_obfuscation,
        "possibleObfuscation",
    );
    push_signal(
        &mut signals,
        supply_chain.high_entropy_strings,
        "highEntropyStrings",
    );
    push_signal(&mut signals, supply_chain.minified, "minified");
    push_signal(&mut signals, supply_chain.telemetry, "telemetry");
    push_signal(&mut signals, supply_chain.url_strings, "urlStrings");
    push_signal(&mut signals, supply_chain.protestware, "protestware");
    signals
}

fn push_signal(signals: &mut Vec<String>, active: bool, name: &str) {
    if active {
        signals.push(name.to_string());
    }
}

fn path_to_slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn extend_oversized_source_files(
    target: &mut Vec<OversizedSourceFileEvidence>,
    source: Vec<OversizedSourceFileEvidence>,
) {
    let remaining = MAX_OVERSIZED_SOURCE_FILE_EVIDENCE.saturating_sub(target.len());
    target.extend(source.into_iter().take(remaining));
}

fn accumulate_result(
    source_tags: &mut SourceTags,
    supply_chain_tags: &mut SupplyChainTags,
    all_url_domains: &mut Vec<String>,
    total_code_lines: &mut usize,
    total_export_count: &mut usize,
    meta: &mut AnalysisMeta,
    result: FileAnalysisResult,
) {
    let oversized = !result.oversized_source_files.is_empty();
    *source_tags = source::merge_source_tags(source_tags, &result.source);
    *supply_chain_tags =
        supply_chain::merge_supply_chain_tags(supply_chain_tags, &result.supply_chain);
    all_url_domains.extend(result.url_domains);
    *total_code_lines += result.total_code_lines;
    *total_export_count += result.total_export_count;
    meta.files_scanned += result.files_scanned;
    meta.bytes_scanned += result.bytes_scanned;
    extend_oversized_source_files(
        &mut meta.oversized_source_files,
        result.oversized_source_files,
    );
    if oversized {
        meta.limit_reached = true;
    }
}

fn merge_with_limits(analyzer: &mut PackageAnalyzer, result: FileAnalysisResult) {
    if analyzer.bytes_scanned + result.bytes_scanned > MAX_TOTAL_SCAN_BYTES {
        analyzer.limit_reached = true;
        return;
    }
    analyzer.merge(result);
}

/// Sequential file scanning (for packages with < 20 files).
fn analyze_files_sequential(package_dir: &Path, files: &[std::path::PathBuf]) -> AccumulatedResult {
    let mut source_tags = SourceTags::default();
    let mut supply_chain_tags = SupplyChainTags::default();
    let mut meta = AnalysisMeta::default();
    let mut all_url_domains = Vec::new();
    let mut total_code_lines = 0usize;
    let mut total_export_count = 0usize;
    let mut comment_buf = Vec::new();

    for file_path in files {
        if meta.files_scanned >= MAX_FILES_PER_PACKAGE {
            meta.limit_reached = true;
            break;
        }
        if let Some(result) = analyze_single_file(package_dir, file_path, &mut comment_buf) {
            if meta.bytes_scanned + result.bytes_scanned > MAX_TOTAL_SCAN_BYTES {
                meta.limit_reached = true;
                break;
            }
            accumulate_result(
                &mut source_tags,
                &mut supply_chain_tags,
                &mut all_url_domains,
                &mut total_code_lines,
                &mut total_export_count,
                &mut meta,
                result,
            );
        }
    }

    AccumulatedResult {
        source: source_tags,
        supply_chain: supply_chain_tags,
        url_domains: all_url_domains,
        total_code_lines,
        total_export_count,
        meta,
    }
}

/// Parallel file scanning using rayon (for packages with 20+ files).
fn analyze_files_parallel(package_dir: &Path, files: &[std::path::PathBuf]) -> AccumulatedResult {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let files_scanned = AtomicUsize::new(0);
    let bytes_scanned = AtomicU64::new(0);

    // Analyze all files in parallel, collecting results
    let results: Vec<FileAnalysisResult> = files
        .par_iter()
        .map_init(Vec::new, |comment_buf, file_path| {
            // Approximate limit checks (may slightly overshoot — acceptable for safety limits)
            if files_scanned.load(Ordering::Relaxed) >= MAX_FILES_PER_PACKAGE {
                return None;
            }
            if bytes_scanned.load(Ordering::Relaxed) > MAX_TOTAL_SCAN_BYTES {
                return None;
            }

            let result = analyze_single_file(package_dir, file_path, comment_buf)?;
            files_scanned.fetch_add(result.files_scanned, Ordering::Relaxed);
            bytes_scanned.fetch_add(result.bytes_scanned, Ordering::Relaxed);
            Some(result)
        })
        .filter_map(|result| result)
        .collect();

    // Merge all results
    let mut source_tags = SourceTags::default();
    let mut supply_chain_tags = SupplyChainTags::default();
    let mut all_url_domains = Vec::new();
    let mut total_code_lines = 0usize;
    let mut total_export_count = 0usize;
    let mut meta = AnalysisMeta::default();

    for result in results {
        accumulate_result(
            &mut source_tags,
            &mut supply_chain_tags,
            &mut all_url_domains,
            &mut total_code_lines,
            &mut total_export_count,
            &mut meta,
            result,
        );
    }

    let limit_reached = files_scanned.load(Ordering::Relaxed) >= MAX_FILES_PER_PACKAGE
        || bytes_scanned.load(Ordering::Relaxed) > MAX_TOTAL_SCAN_BYTES;
    meta.limit_reached |= limit_reached;

    AccumulatedResult {
        source: source_tags,
        supply_chain: supply_chain_tags,
        url_domains: all_url_domains,
        total_code_lines,
        total_export_count,
        meta,
    }
}

/// Collect source files from a package directory, filtered by extension.
///
/// Skips `node_modules/`, hidden files/directories, `.d.ts` files, and `.map` files.
/// Returns paths sorted for deterministic analysis order.
fn collect_source_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    collect_source_files_recursive(dir, &mut files);
    files.sort();
    files
}

fn collect_source_files_recursive(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };

        if lpm_common::is_symlink_or_junction(&metadata) {
            continue;
        }

        // Skip hidden files/directories
        if name_str.starts_with('.') {
            continue;
        }

        if metadata.is_dir() {
            // Skip node_modules (shouldn't exist in store, but defensive)
            if name_str == "node_modules" || name_str == "__tests__" || name_str == "test" {
                continue;
            }
            collect_source_files_recursive(&path, files);
            continue;
        }

        // Skip non-source files
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        if !SOURCE_EXTENSIONS.contains(&ext) {
            continue;
        }

        // Skip .d.ts type declaration files (no runtime behavior)
        if name_str.ends_with(".d.ts")
            || name_str.ends_with(".d.mts")
            || name_str.ends_with(".d.cts")
        {
            continue;
        }

        // Skip .map source maps
        if name_str.ends_with(".map") {
            continue;
        }

        files.push(path);
    }
}

/// Analyze package.json for manifest tags.
fn analyze_package_manifest(package_dir: &Path) -> ManifestTags {
    let pkg_json_path = package_dir.join("package.json");
    let content = match lpm_common::read_text_file_capped(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(c) => c,
        Err(_) => return ManifestTags::default(),
    };

    analyze_package_manifest_content(&content)
}

fn analyze_package_manifest_bytes(content: &[u8]) -> ManifestTags {
    std::str::from_utf8(content)
        .map(analyze_package_manifest_content)
        .unwrap_or_default()
}

fn analyze_package_manifest_content(content: &str) -> ManifestTags {
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return ManifestTags::default(),
    };

    let license = parsed.get("license").and_then(|v| v.as_str());
    let private_package = parsed
        .get("private")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Also check "licence" typo
    let license = license.or_else(|| parsed.get("licence").and_then(|v| v.as_str()));

    let dependencies = parse_deps_map(parsed.get("dependencies"));
    let dev_dependencies = parse_deps_map(parsed.get("devDependencies"));
    let optional_dependencies = parse_deps_map(parsed.get("optionalDependencies"));

    manifest::analyze_manifest_with_privacy(
        license,
        private_package,
        dependencies.as_ref(),
        dev_dependencies.as_ref(),
        optional_dependencies.as_ref(),
    )
}

/// Parse a JSON value into a HashMap<String, String> for dependency maps.
fn parse_deps_map(value: Option<&serde_json::Value>) -> Option<HashMap<String, String>> {
    let obj = value?.as_object()?;
    let mut map = HashMap::with_capacity(obj.len());
    for (key, val) in obj {
        if let Some(v) = val.as_str() {
            map.insert(key.clone(), v.to_string());
        }
    }
    Some(map)
}

/// Streaming package analyzer for the fused-scan path.
///
/// Fed one file at a time during tar extraction — callers pipe each
/// scannable entry's `(relative_path, bytes)` through [`PackageAnalyzer::feed`]
/// while the extractor walks the archive. Once extraction completes,
/// [`PackageAnalyzer::finalize`] reads `package.json` from the now-written
/// staging directory, runs the manifest-level analysis, and returns a
/// [`PackageAnalysis`] that is byte-compatible with [`analyze_package`].
///
/// Semantics match the two-pass path exactly — same tags, same
/// deduplication, same limits. The difference is purely operational:
/// we scan bytes the extractor already had in hand instead of walking
/// the just-written directory a second time.
#[derive(Debug, Default)]
pub struct PackageAnalyzer {
    source: SourceTags,
    supply_chain: SupplyChainTags,
    url_domains: Vec<String>,
    oversized_source_files: Vec<OversizedSourceFileEvidence>,
    total_code_lines: usize,
    total_export_count: usize,
    files_scanned: usize,
    bytes_scanned: u64,
    limit_reached: bool,
    source_scan_ns: u128,
}

impl PackageAnalyzer {
    /// Create an empty analyzer. Cheap — no allocations beyond defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Does this tar entry qualify for source analysis?
    ///
    /// Returns `true` iff:
    /// - Extension is in `SOURCE_EXTENSIONS` (js/mjs/cjs/ts/mts/cts/jsx/tsx)
    /// - Filename is not `.d.ts` / `.d.mts` / `.d.cts` / `.map`
    /// - No path component is `node_modules` / `__tests__` / `test`
    /// - No path component starts with `.` (hidden files/dirs)
    ///
    /// The size cap is intentionally NOT checked here: oversized files still
    /// need lightweight metadata via [`PackageAnalyzer::feed_oversized_source_file`].
    ///
    /// Mirrors the `collect_source_files_recursive` filter exactly so the
    /// fused path scans the same set of files as the two-pass path.
    pub fn should_scan(relative_path: &Path, _size: u64) -> bool {
        for component in relative_path.components() {
            let name = match component {
                std::path::Component::Normal(s) => s.to_string_lossy(),
                _ => continue,
            };
            if name.starts_with('.')
                || name == "node_modules"
                || name == "__tests__"
                || name == "test"
            {
                return false;
            }
        }

        let name_str = relative_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();

        if name_str.ends_with(".d.ts")
            || name_str.ends_with(".d.mts")
            || name_str.ends_with(".d.cts")
            || name_str.ends_with(".map")
        {
            return false;
        }

        let ext = relative_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        SOURCE_EXTENSIONS.contains(&ext)
    }

    fn should_scan_directory(relative_path: &Path) -> bool {
        relative_path.components().all(|component| {
            let std::path::Component::Normal(name) = component else {
                return false;
            };
            let name = name.to_string_lossy();
            !name.starts_with('.')
                && name != "node_modules"
                && name != "__tests__"
                && name != "test"
        })
    }

    /// Should the extractor buffer this source entry for full byte-level scanning?
    pub fn should_buffer_source(relative_path: &Path, size: u64) -> bool {
        Self::should_scan(relative_path, size) && size <= MAX_FILE_SIZE
    }

    /// Feed one scannable file's bytes. Respects per-package limits
    /// (`MAX_FILES_PER_PACKAGE` / `MAX_TOTAL_SCAN_BYTES`) — once either
    /// is hit, subsequent `feed` calls are no-ops and `limit_reached`
    /// flips to `true` in the final meta.
    pub fn feed(&mut self, relative_path: &Path, bytes: &[u8]) {
        if self.files_scanned >= MAX_FILES_PER_PACKAGE {
            self.limit_reached = true;
            return;
        }
        let filename = relative_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();

        if bytes.len() as u64 > MAX_FILE_SIZE {
            let scan_start = std::time::Instant::now();
            let sample = oversized_source_sample_from_bytes(bytes);
            let mut comment_buf = Vec::new();
            let result = analyze_oversized_source_sample(
                relative_path,
                bytes.len() as u64,
                &sample,
                &mut comment_buf,
            );
            merge_with_limits(self, result);
            self.source_scan_ns = self
                .source_scan_ns
                .saturating_add(scan_start.elapsed().as_nanos());
            return;
        }

        if self.bytes_scanned + bytes.len() as u64 > MAX_TOTAL_SCAN_BYTES {
            self.limit_reached = true;
            return;
        }

        let scan_start = std::time::Instant::now();
        let result = analyze_bytes(&filename, bytes);
        self.merge(result);
        self.source_scan_ns = self
            .source_scan_ns
            .saturating_add(scan_start.elapsed().as_nanos());
    }

    /// Sample an oversized source file from disk after extraction.
    pub fn feed_oversized_source_file(
        &mut self,
        relative_path: &Path,
        full_path: &Path,
        size: u64,
    ) {
        if !Self::should_scan(relative_path, size) || size <= MAX_FILE_SIZE {
            return;
        }
        let scan_start = std::time::Instant::now();
        let mut comment_buf = Vec::new();
        let result =
            analyze_oversized_source_file(relative_path, full_path, size, &mut comment_buf);
        merge_with_limits(self, result);
        self.source_scan_ns = self
            .source_scan_ns
            .saturating_add(scan_start.elapsed().as_nanos());
    }

    /// Record an "oversized minified" file without reading its bytes.
    /// Used by the fused path for files that pass the
    /// `should_scan` extension test but exceed 2 MB and match a minified
    /// filename pattern — we still want the `minified: true` tag without
    /// pulling megabytes into RAM.
    pub fn feed_oversized_minified(&mut self, relative_path: &Path, size: u64) {
        let filename = relative_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if supply_chain::is_minified_filename(&filename) {
            let scan_start = std::time::Instant::now();
            let result = oversized_minified_result(relative_path, size);
            merge_with_limits(self, result);
            self.source_scan_ns = self
                .source_scan_ns
                .saturating_add(scan_start.elapsed().as_nanos());
        }
    }

    /// Return the accumulated time spent running source detectors.
    pub fn source_scan_ns(&self) -> u128 {
        self.source_scan_ns
    }

    fn merge(&mut self, result: FileAnalysisResult) {
        let oversized = !result.oversized_source_files.is_empty();
        self.source = source::merge_source_tags(&self.source, &result.source);
        self.supply_chain =
            supply_chain::merge_supply_chain_tags(&self.supply_chain, &result.supply_chain);
        self.url_domains.extend(result.url_domains);
        extend_oversized_source_files(
            &mut self.oversized_source_files,
            result.oversized_source_files,
        );
        self.total_code_lines += result.total_code_lines;
        self.total_export_count += result.total_export_count;
        self.files_scanned += result.files_scanned;
        self.bytes_scanned += result.bytes_scanned;
        if oversized {
            self.limit_reached = true;
        }
    }

    /// Complete the analysis: read the package manifest from disk,
    /// deduplicate URL domains, compute the package-level `trivial`
    /// tag, and build the final [`PackageAnalysis`]. Mirrors the tail
    /// of [`analyze_package`] exactly so outputs are byte-for-byte
    /// compatible with the two-pass path.
    pub fn finalize(mut self, package_dir: &Path) -> PackageAnalysis {
        if self.files_scanned > 0 {
            self.supply_chain.trivial = self.total_code_lines < 10 && self.total_export_count <= 1;
        }

        self.url_domains.sort_unstable();
        self.url_domains.dedup();

        let meta = AnalysisMeta {
            files_scanned: self.files_scanned,
            bytes_scanned: self.bytes_scanned,
            limit_reached: self.limit_reached,
            url_domains: self.url_domains,
            oversized_source_files: self.oversized_source_files,
        };

        let manifest_tags = analyze_package_manifest(package_dir);
        let analyzed_at = chrono::Utc::now().to_rfc3339();

        PackageAnalysis {
            version: SCHEMA_VERSION,
            analyzed_at,
            source: self.source,
            supply_chain: self.supply_chain,
            manifest: manifest_tags,
            meta,
        }
    }
}

/// Read a cached `.lpm-security.json` file from a package directory.
///
/// Returns `None` if:
/// - File doesn't exist (never analyzed)
/// - File can't be parsed
/// - Schema version is outdated (needs re-analysis)
pub fn read_cached_analysis(package_dir: &Path) -> Option<PackageAnalysis> {
    let path = package_dir.join(".lpm-security.json");
    let content =
        lpm_common::read_capped_state_file(&path, lpm_common::STATE_FILE_SIZE_CAP_BYTES).ok()??;
    let analysis: PackageAnalysis = serde_json::from_slice(&content).ok()?;

    // Check schema version — re-analyze unless semantics match exactly.
    if analysis.version != SCHEMA_VERSION {
        tracing::debug!(
            "cached analysis version {} != current {SCHEMA_VERSION}, needs re-analysis",
            analysis.version
        );
        return None;
    }

    Some(analysis)
}

/// Write analysis results to `.lpm-security.json` in a package directory.
pub fn write_cached_analysis(
    package_dir: &Path,
    analysis: &PackageAnalysis,
) -> Result<(), std::io::Error> {
    let path = package_dir.join(".lpm-security.json");
    let json = serde_json::to_string_pretty(analysis).map_err(std::io::Error::other)?;
    std::fs::write(&path, json)
}

/// Atomically replace `.lpm-security.json` in an already-published package
/// directory.
pub fn write_cached_analysis_atomic(
    package_dir: &Path,
    analysis: &PackageAnalysis,
) -> Result<(), std::io::Error> {
    let path = package_dir.join(".lpm-security.json");
    let json = serde_json::to_string_pretty(analysis).map_err(std::io::Error::other)?;
    lpm_common::write_file_atomic(&path, json)
}

/// Backfill a missing, malformed, or outdated analysis cache.
///
/// Returns `true` when a new cache was written and `false` when the existing
/// cache already uses the current schema.
pub fn backfill_cached_analysis(package_dir: &Path) -> Result<bool, std::io::Error> {
    if read_cached_analysis(package_dir).is_some() {
        return Ok(false);
    }
    let analysis = analyze_package(package_dir);
    write_cached_analysis_atomic(package_dir, &analysis)?;
    Ok(true)
}

/// Analyze a package directory, using cache if available.
///
/// This is the primary entry point for the store integration:
/// 1. Check for `.lpm-security.json` (cache hit → return immediately)
/// 2. Run full analysis
/// 3. Write cache
/// 4. Return results
pub fn analyze_package_cached(package_dir: &Path) -> PackageAnalysis {
    // Cache hit
    if let Some(cached) = read_cached_analysis(package_dir) {
        return cached;
    }

    // Cache miss — run analysis
    let analysis = analyze_package(package_dir);

    // Write cache (best-effort, don't fail install if write fails)
    if let Err(e) = write_cached_analysis(package_dir, &analysis) {
        tracing::warn!("failed to write .lpm-security.json: {e}");
    }

    analysis
}

/// Check if ANY dangerous tags are set (Critical or High severity).
///
/// Used by post-install summary to decide whether to show the security section.
pub fn has_dangerous_tags(analysis: &PackageAnalysis) -> bool {
    // Critical
    analysis.supply_chain.obfuscated
		|| analysis.supply_chain.protestware
		|| analysis.supply_chain.high_entropy_strings
	// High
		|| analysis.source.eval
		|| analysis.source.child_process
		|| analysis.source.shell
		|| analysis.source.dynamic_require
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_package(dir: &Path, files: &[(&str, &str)]) {
        for (path, content) in files {
            let file_path = dir.join(path);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&file_path, content).unwrap();
        }
    }

    // ── Package analysis ──────────────────────────────────────

    #[test]
    fn analyze_simple_package() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"test","version":"1.0.0","license":"MIT"}"#,
                ),
                (
                    "index.js",
                    r#"const fs = require("fs"); module.exports = fs.readFileSync;"#,
                ),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.source.filesystem);
        assert!(!analysis.source.network);
        assert!(!analysis.source.eval);
        assert!(!analysis.manifest.copyleft_license);
        assert!(!analysis.manifest.no_license);
        assert_eq!(analysis.meta.files_scanned, 1);
    }

    #[test]
    fn analyze_package_with_network_and_eval() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("lib/http.js", "fetch('https://api.example.com')"),
                ("lib/dynamic.js", "eval(code)"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.source.network);
        assert!(analysis.source.eval);
        assert!(!analysis.source.filesystem);
        assert_eq!(analysis.meta.files_scanned, 2);
        assert!(!analysis.meta.url_domains.is_empty());
    }

    #[test]
    fn analyze_package_gpl_license() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"GPL-3.0"}"#),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.manifest.copyleft_license);
        assert!(!analysis.manifest.no_license);
    }

    #[cfg(unix)]
    #[test]
    fn analyze_package_does_not_follow_nested_directory_symlinks() {
        use std::os::unix::fs::symlink;

        let package = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[(
                "package.json",
                r#"{"name":"safe","version":"1.0.0","license":"MIT"}"#,
            )],
        );
        create_test_package(outside.path(), &[("outside.js", "eval('outside')")]);
        symlink(outside.path(), package.path().join("linked-outside")).unwrap();

        let analysis = analyze_package(package.path());

        assert!(
            !analysis.source.eval,
            "behavioral analysis must not leave the selected package through nested symlinks"
        );
    }

    #[test]
    fn capability_analysis_matches_path_analysis_for_parallel_packages() {
        let package = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[(
                "package.json",
                r#"{"name":"parallel","version":"1.0.0","license":"MIT"}"#,
            )],
        );
        for index in 0..24 {
            fs::write(
                package.path().join(format!("source-{index}.js")),
                format!("export const value{index} = fetch('https://example.test/{index}');\n"),
            )
            .unwrap();
        }
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        let path_analysis = analyze_package(package.path());
        let capability_analysis = analyze_package_from_open_dir(&directory);
        let mut path_json = serde_json::to_value(path_analysis).unwrap();
        let mut capability_json = serde_json::to_value(capability_analysis).unwrap();
        path_json["analyzedAt"] = serde_json::Value::Null;
        capability_json["analyzedAt"] = serde_json::Value::Null;

        assert_eq!(capability_json, path_json);
    }

    #[test]
    fn fused_capability_analysis_fingerprints_the_bytes_it_analyzes() {
        let package = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"fused","version":"1.0.0","license":"MIT"}"#,
                ),
                ("index.js", "eval('same bytes');\n"),
                ("ignored.txt", "this file does not affect analysis"),
            ],
        );
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        let (analysis, fused_fingerprint) =
            analyze_package_from_open_dir_with_fingerprint(&directory);
        let standalone_fingerprint = package_input_fingerprint_from_open_dir(&directory).unwrap();

        assert!(analysis.source.eval);
        assert_eq!(
            fused_fingerprint.as_deref(),
            Some(standalone_fingerprint.as_str())
        );

        fs::write(package.path().join("index.js"), "module.exports = 1;\n").unwrap();
        assert_ne!(
            package_input_fingerprint_from_open_dir(&directory).unwrap(),
            standalone_fingerprint
        );
    }

    #[test]
    fn warm_fingerprint_rejects_a_manifest_larger_than_the_configuration_cap() {
        let package = tempfile::tempdir().unwrap();
        let manifest = std::fs::File::create(package.path().join("package.json")).unwrap();
        manifest
            .set_len(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1)
            .unwrap();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        let error = package_input_fingerprint_from_open_dir(&directory).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn capability_scan_prefix_is_deterministic_at_the_package_byte_limit() {
        let files = (0..30)
            .map(|index| CapSourceFile {
                path: format!("source-{index:02}.js").into(),
                size: MAX_FILE_SIZE,
            })
            .collect::<Vec<_>>();

        let (selected, limit_reached) = cap_scan_prefix(&files);

        assert!(limit_reached);
        assert_eq!(selected.len(), 25);
        assert_eq!(selected[0].path, Path::new("source-00.js"));
        assert_eq!(selected[24].path, Path::new("source-24.js"));
    }

    #[test]
    fn capability_file_limit_selects_lexicographically_first_paths() {
        let package = tempfile::tempdir().unwrap();
        for index in (0..=MAX_FILES_PER_PACKAGE).rev() {
            fs::write(
                package.path().join(format!("source-{index:05}.js")),
                "module.exports = 1;\n",
            )
            .unwrap();
        }
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();
        let mut files = CapSourceFiles::new();
        let mut limit_reached = false;

        collect_cap_fingerprint_files(&directory, Path::new(""), &mut files, &mut limit_reached)
            .unwrap();
        let files = files.into_sorted_vec();

        assert!(limit_reached);
        assert_eq!(files.len(), MAX_FILES_PER_PACKAGE);
        assert_eq!(files.first().unwrap().path, Path::new("source-00000.js"));
        assert_eq!(files.last().unwrap().path, Path::new("source-04999.js"));
    }

    #[cfg(unix)]
    #[test]
    fn capability_analysis_keeps_the_open_package_root_after_path_replacement() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let package = parent.path().join("package");
        create_test_package(
            &package,
            &[
                (
                    "package.json",
                    r#"{"name":"safe","version":"1.0.0","license":"MIT"}"#,
                ),
                ("index.js", "module.exports = 1;\n"),
            ],
        );
        create_test_package(
            outside.path(),
            &[
                ("package.json", r#"{"name":"outside","version":"9.0.0"}"#),
                ("index.js", "eval('outside')\n"),
            ],
        );
        let directory =
            cap_std::fs::Dir::open_ambient_dir(&package, cap_std::ambient_authority()).unwrap();
        fs::rename(&package, parent.path().join("detached")).unwrap();
        symlink(outside.path(), &package).unwrap();

        let analysis = analyze_package_from_open_dir(&directory);

        assert!(!analysis.source.eval);
        assert!(!analysis.manifest.no_license);
        assert_eq!(analysis.meta.files_scanned, 1);
    }

    #[cfg(windows)]
    #[test]
    fn capability_analysis_does_not_follow_nested_directory_junctions() {
        let package = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[(
                "package.json",
                r#"{"name":"safe","version":"1.0.0","license":"MIT"}"#,
            )],
        );
        create_test_package(outside.path(), &[("outside.js", "eval('outside')")]);
        lpm_common::create_dir_symlink_or_junction(
            outside.path(),
            &package.path().join("linked-outside"),
        )
        .unwrap();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        let analysis = analyze_package_from_open_dir(&directory);

        assert!(!analysis.source.eval);
    }

    #[test]
    fn analyze_package_no_license() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test"}"#),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.manifest.no_license);
    }

    #[test]
    fn analyze_private_package_without_license() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","private":true}"#),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(!analysis.manifest.no_license);
    }

    #[test]
    fn analyze_package_git_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[(
                "package.json",
                r#"{"name":"test","license":"MIT","dependencies":{"my-fork":"github:owner/repo"}}"#,
            )],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.manifest.git_dependency);
    }

    #[test]
    fn skips_dts_files() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.d.ts", "export declare function readFile(): void;"),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        // .d.ts should be skipped — readFile in declaration shouldn't trigger filesystem
        assert!(!analysis.source.filesystem);
        assert_eq!(analysis.meta.files_scanned, 1);
    }

    #[test]
    fn skips_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "module.exports = 42"),
                ("node_modules/evil/index.js", "eval('attack')"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(!analysis.source.eval);
        assert_eq!(analysis.meta.files_scanned, 1);
    }

    #[test]
    fn skips_non_source_files() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "module.exports = 42"),
                ("styles.css", "body { color: red }"),
                ("data.json", r#"{"key": "value"}"#),
                ("readme.md", "# Hello"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert_eq!(analysis.meta.files_scanned, 1); // only index.js
    }

    #[test]
    fn scans_minified_filenames() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("dist/app.min.js", r#"eval("something")"#),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.supply_chain.minified);
        assert!(analysis.source.eval);
    }

    #[test]
    fn analyze_package_samples_oversized_source_files() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[("package.json", r#"{"name":"test","license":"MIT"}"#)],
        );
        let source_path = dir.path().join("dist/big.js");
        fs::create_dir_all(source_path.parent().unwrap()).unwrap();

        let mut code =
            String::from("fetch('https://oversized.example/payload'); process.env.TOKEN;\n");
        code.push_str(&"a".repeat(MAX_FILE_SIZE as usize + 1024));
        code.push_str("const { exec } = require('child_process'); exec('id');\n");
        fs::write(&source_path, code).unwrap();

        let analysis = analyze_package(dir.path());
        let oversized = analysis
            .meta
            .oversized_source_files
            .first()
            .expect("oversized evidence should be recorded");

        assert_eq!(oversized.path, "dist/big.js");
        assert!(analysis.source.network);
        assert!(analysis.source.child_process);
        assert!(analysis.source.environment_vars);
        assert!(analysis.meta.limit_reached);
        assert_eq!(analysis.meta.files_scanned, 0);
        assert!(oversized.signals.contains(&"network".to_string()));
        assert!(oversized.signals.contains(&"childProcess".to_string()));
        assert!(
            oversized
                .url_domains
                .contains(&"oversized.example".to_string())
        );
        assert!(oversized.sample_bytes_scanned < oversized.size_bytes);
    }

    #[test]
    fn package_analyzer_samples_oversized_sources_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[("package.json", r#"{"name":"test","license":"MIT"}"#)],
        );
        let relative_path = Path::new("dist/huge.bundle.js");
        let full_path = dir.path().join(relative_path);
        fs::create_dir_all(full_path.parent().unwrap()).unwrap();

        let mut code = String::from("const ws = new WebSocket('wss://oversized.example/ws');\n");
        code.push_str(&"b".repeat(MAX_FILE_SIZE as usize + 1024));
        code.push_str("\neval('42');\n");
        fs::write(&full_path, code).unwrap();
        let size = fs::metadata(&full_path).unwrap().len();

        assert!(PackageAnalyzer::should_scan(relative_path, size));
        assert!(!PackageAnalyzer::should_buffer_source(relative_path, size));

        let mut analyzer = PackageAnalyzer::new();
        analyzer.feed_oversized_source_file(relative_path, &full_path, size);
        let analysis = analyzer.finalize(dir.path());

        let oversized = analysis
            .meta
            .oversized_source_files
            .first()
            .expect("oversized evidence should be recorded");
        assert_eq!(oversized.path, "dist/huge.bundle.js");
        assert!(analysis.source.web_socket);
        assert!(analysis.source.eval);
        assert!(analysis.supply_chain.minified);
        assert!(oversized.minified_filename);
    }

    #[test]
    fn detect_trivial_package() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"is-odd","license":"MIT"}"#),
                ("index.js", "module.exports = n => n % 2 === 1;\n"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.supply_chain.trivial);
    }

    #[test]
    fn not_trivial_real_package() {
        let dir = tempfile::tempdir().unwrap();
        let code = (0..50)
            .map(|i| format!("export function fn{i}() {{ return {i}; }}"))
            .collect::<Vec<_>>()
            .join("\n");
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"real-pkg","license":"MIT"}"#),
                ("index.js", &code),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(!analysis.supply_chain.trivial);
    }

    // ── Cache ─────────────────────────────────────────────────

    #[test]
    fn cache_write_and_read() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "eval('code')"),
            ],
        );

        let analysis = analyze_package(dir.path());
        write_cached_analysis(dir.path(), &analysis).unwrap();

        let cached = read_cached_analysis(dir.path()).unwrap();
        assert_eq!(cached.source.eval, analysis.source.eval);
        assert_eq!(cached.version, SCHEMA_VERSION);
    }

    #[test]
    fn cache_outdated_version_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".lpm-security.json");
        // Write a cache with old schema version
        fs::write(
			&path,
			r#"{"version":1,"analyzedAt":"2026-01-01T00:00:00Z","source":{},"supplyChain":{},"manifest":{},"meta":{}}"#,
		)
		.unwrap();

        assert!(read_cached_analysis(dir.path()).is_none());
    }

    #[test]
    fn cache_future_version_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".lpm-security.json");
        let mut analysis = analyze_package(dir.path());
        analysis.version = SCHEMA_VERSION + 1;
        fs::write(&path, serde_json::to_vec(&analysis).unwrap()).unwrap();

        assert!(read_cached_analysis(dir.path()).is_none());
    }

    #[test]
    fn backfill_cached_analysis_replaces_malformed_cache_with_current_analysis() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "eval('code')"),
            ],
        );
        fs::write(dir.path().join(".lpm-security.json"), "{not-json").unwrap();

        assert!(backfill_cached_analysis(dir.path()).unwrap());
        let cached = read_cached_analysis(dir.path()).unwrap();
        assert_eq!(cached.version, SCHEMA_VERSION);
        assert!(cached.source.eval);
    }

    #[test]
    fn backfill_cached_analysis_preserves_current_cache() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "eval('code')"),
            ],
        );
        let analysis = analyze_package(dir.path());
        write_cached_analysis(dir.path(), &analysis).unwrap();
        let cache_path = dir.path().join(".lpm-security.json");
        let before = fs::read(&cache_path).unwrap();
        fs::write(dir.path().join("index.js"), "module.exports = 42").unwrap();

        assert!(!backfill_cached_analysis(dir.path()).unwrap());
        assert_eq!(fs::read(cache_path).unwrap(), before);
    }

    #[test]
    fn analyze_cached_uses_cache() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "eval('code')"),
            ],
        );

        // First call writes cache
        let a1 = analyze_package_cached(dir.path());
        assert!(a1.source.eval);

        // Modify the source (but cache should be used)
        fs::write(dir.path().join("index.js"), "module.exports = 42").unwrap();

        let a2 = analyze_package_cached(dir.path());
        // Should still show eval=true because cache is used
        assert!(a2.source.eval);
    }

    // ── has_dangerous_tags ────────────────────────────────────

    #[test]
    fn dangerous_tags_detected() {
        let analysis = PackageAnalysis {
            version: SCHEMA_VERSION,
            analyzed_at: String::new(),
            source: SourceTags {
                eval: true,
                ..Default::default()
            },
            supply_chain: SupplyChainTags::default(),
            manifest: ManifestTags::default(),
            meta: AnalysisMeta::default(),
        };
        assert!(has_dangerous_tags(&analysis));
    }

    #[test]
    fn no_dangerous_tags() {
        let analysis = PackageAnalysis {
            version: SCHEMA_VERSION,
            analyzed_at: String::new(),
            source: SourceTags {
                filesystem: true,
                network: true,
                ..Default::default()
            },
            supply_chain: SupplyChainTags::default(),
            manifest: ManifestTags::default(),
            meta: AnalysisMeta::default(),
        };
        assert!(!has_dangerous_tags(&analysis));
    }

    // ── Comment in string edge case ───────────────────────────

    #[test]
    fn eval_in_comment_not_detected() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "// eval('bad')\nmodule.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(!analysis.source.eval);
    }

    #[test]
    fn eval_in_block_comment_not_detected() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "/* eval('bad') */\nmodule.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(!analysis.source.eval);
    }

    #[test]
    fn url_in_string_not_stripped_as_comment() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                (
                    "index.js",
                    r#"const url = "https://api.example.com"; fetch(url)"#,
                ),
            ],
        );

        let analysis = analyze_package(dir.path());
        // The URL shouldn't be stripped as a comment, and fetch should be detected
        assert!(analysis.source.network);
        assert!(analysis.supply_chain.url_strings);
    }

    // ── Schema version ────────────────────────────────────────

    #[test]
    fn analysis_has_current_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                ("package.json", r#"{"name":"test","license":"MIT"}"#),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert_eq!(analysis.version, SCHEMA_VERSION);
    }

    // ── Edge case: jQuery-style minified (NOT obfuscated) ────────

    #[test]
    fn jquery_minified_not_obfuscated() {
        let dir = tempfile::tempdir().unwrap();
        // Simulate a jQuery-style minified bundle: very long line, normal JS patterns
        let mut long_line = String::with_capacity(15_000);
        long_line.push_str("!function(e,t){\"use strict\";");
        for i in 0..500 {
            long_line.push_str(&format!(
                "var a{i}=e.createElement(\"div\");a{i}.className=\"widget\";t.appendChild(a{i});"
            ));
        }
        long_line.push_str("}(document,document.body);");

        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"jquery","version":"3.7.1","license":"MIT"}"#,
                ),
                ("jquery.js", &long_line),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.supply_chain.minified, "should detect minified");
        assert!(
            !analysis.supply_chain.obfuscated,
            "jQuery-style minified must NOT be flagged as obfuscated"
        );
    }

    // ── Edge case: package with zero JS files ────────────────────

    #[test]
    fn json_only_package_no_source_tags() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"config-data","version":"1.0.0","license":"MIT"}"#,
                ),
                ("data.json", r#"{"key":"value"}"#),
                ("README.md", "# Config Data"),
            ],
        );

        let analysis = analyze_package(dir.path());
        // All source + supply chain tags should be false (no .js files to scan)
        assert!(!analysis.source.eval);
        assert!(!analysis.source.network);
        assert!(!analysis.source.filesystem);
        assert!(!analysis.supply_chain.obfuscated);
        assert!(!analysis.supply_chain.protestware);
        // Manifest tags still checked
        assert!(!analysis.manifest.copyleft_license); // MIT is not copyleft
    }

    // ── Edge case: native .node binary alongside JS ──────────────

    #[test]
    fn native_node_file_detected() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"native-pkg","version":"1.0.0","license":"MIT"}"#,
                ),
                (
                    "index.js",
                    "const binding = require('./build/Release/addon.node')",
                ),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.source.native_bindings);
    }

    // ── Edge case: process.env.NODE_ENV (React pattern) ──────────

    #[test]
    fn process_env_node_env_detected() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"react-thing","version":"1.0.0","license":"MIT"}"#,
                ),
                (
                    "index.js",
                    "if (process.env.NODE_ENV !== 'production') { console.warn('dev mode') }",
                ),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(
            analysis.source.environment_vars,
            "process.env.NODE_ENV IS reading env — should be detected"
        );
    }

    // ── Edge case: GPL-2.0-or-later SPDX expression ──────────────

    #[test]
    fn gpl_2_or_later_spdx() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"gpl-pkg","version":"1.0.0","license":"GPL-2.0-or-later"}"#,
                ),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.manifest.copyleft_license);
    }

    // ── Edge case: MIT OR Apache-2.0 (not copyleft) ──────────────

    #[test]
    fn mit_or_apache_not_copyleft() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"dual-license","version":"1.0.0","license":"MIT OR Apache-2.0"}"#,
                ),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(
            !analysis.manifest.copyleft_license,
            "MIT OR Apache-2.0 should NOT be copyleft"
        );
    }

    // ── Edge case: mixed project, partial cache ──────────────────

    #[test]
    fn partial_cache_missing_analysis() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"test","version":"1.0.0","license":"MIT"}"#,
                ),
                ("index.js", "const x = 1"),
            ],
        );

        // First call — no cache, full analysis
        let a1 = analyze_package_cached(dir.path());
        assert_eq!(a1.version, SCHEMA_VERSION);

        // Cache should exist now
        assert!(dir.path().join(".lpm-security.json").exists());

        // Second call — should use cache (fast path)
        let a2 = analyze_package_cached(dir.path());
        assert_eq!(a2.source, a1.source);
        assert_eq!(a2.supply_chain, a1.supply_chain);
        assert_eq!(a2.manifest, a1.manifest);
    }

    // ── Edge case: corrupted cache file (graceful degradation) ───

    #[test]
    fn corrupted_cache_triggers_reanalysis() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"test","version":"1.0.0","license":"MIT"}"#,
                ),
                ("index.js", "const x = 1"),
            ],
        );

        // Write corrupted cache
        std::fs::write(dir.path().join(".lpm-security.json"), "not json").unwrap();

        // read_cached_analysis should return None for corrupted cache
        assert!(read_cached_analysis(dir.path()).is_none());

        // analyze_package_cached should re-analyze and return valid result
        let analysis = analyze_package_cached(dir.path());
        assert_eq!(analysis.version, SCHEMA_VERSION);
    }
}
