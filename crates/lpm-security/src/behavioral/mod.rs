//! Client-side behavioral analysis for all packages (npm + @lpm.dev).
//!
//! Detects 23 security-relevant tags across three groups:
//! - **Source tags** (10): API usage patterns (filesystem, network, eval, etc.)
//! - **Supply chain tags** (8): Obfuscation confidence, entropy, minified, telemetry, etc.
//! - **Manifest tags** (5): License + dependency configuration issues
//!
//! Explicit audits and opted-in installs scan source without executing package code.
//! Cached results are invalidated when the schema or package fingerprint changes.
//!
//! Regex matching has linear time bounds. Syntax analysis distinguishes bindings
//! from unrelated names. Oversized files receive bounded head and tail samples.
//! Package byte and file limits produce explicit partial-coverage metadata.

mod bindings;
mod evidence;
pub mod manifest;
pub mod release;
pub mod roles;
pub mod secrets;
pub mod source;
pub mod supply_chain;
mod syntax;
mod threats;

pub use evidence::SourceEvidence;

use manifest::ManifestTags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use source::SourceTags;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use supply_chain::SupplyChainTags;

/// Current schema version for `.lpm-security.json`.
/// Bump this when adding new tags or changing tag semantics — cached
/// files with older versions will be automatically re-analyzed.
pub const SCHEMA_VERSION: u32 = 14;

/// Maximum file size for a full scan. Larger source files receive bounded samples.
const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024;

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

/// Paths a tag's [`TagFiles`] lists; `file_count` counts the rest.
const MAX_TAG_FILES: usize = 5;

/// How much of a package a [`PackageAnalyzer`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanLimits {
    /// A source file up to this size is read whole.
    pub full_file_bytes: u64,
    /// Bytes read from each end of a larger source file.
    pub sample_bytes: usize,
    /// Source bytes read across the package before the rest is skipped.
    pub total_bytes: u64,
    /// Source files read before the rest are skipped.
    pub files: usize,
}

impl ScanLimits {
    /// Installs and audits, which analyze every package of a project.
    pub const INSTALL: Self = Self {
        full_file_bytes: MAX_FILE_SIZE,
        sample_bytes: OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES,
        total_bytes: MAX_TOTAL_SCAN_BYTES,
        files: MAX_FILES_PER_PACKAGE,
    };

    /// A registry's analysis of one published release.
    pub const REGISTRY: Self = Self {
        full_file_bytes: 8 * 1024 * 1024,
        sample_bytes: 1024 * 1024,
        total_bytes: 64 * 1024 * 1024,
        files: MAX_FILES_PER_PACKAGE,
    };
}

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
    /// Package manifest tags (6).
    pub manifest: ManifestTags,
    /// Additional metadata (file count, URL domains, etc.)
    pub meta: AnalysisMeta,
}

/// Metadata about the analysis run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisMeta {
    /// Up to three deterministic examples per behavioral rule; not an exhaustive match list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<SourceEvidence>,
    /// Number of source files scanned.
    #[serde(default)]
    pub files_scanned: usize,
    /// Source files whose syntax could not be completely analyzed.
    #[serde(default)]
    pub unparsed_files: usize,
    /// Input discovery or a selected input read failed.
    #[serde(default)]
    pub input_incomplete: bool,
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
    /// Source files read only at each end.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub sampled_files: usize,
    /// Source files left unread past the file or byte limit.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped_files: usize,
    /// The files each tag came from, by registry tag key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tag_files: BTreeMap<String, TagFiles>,
    /// Tags only test files showed, sorted. The tag fields leave them out:
    /// a test the package doesn't run on install or export doesn't run when
    /// the package is used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test_only_tags: Vec<String>,
    /// The `eval()` and `new Function()` calls of the files the tag fields
    /// cover, as the eval tag finds them.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub eval_calls: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// The files a tag came from.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TagFiles {
    /// Up to five paths: files the package runs first, then tests, each in
    /// path order.
    pub files: Vec<String>,
    /// Every file that showed the tag.
    pub file_count: usize,
    /// Each of those files is a test the package doesn't run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tests_only: bool,
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
/// The directory holds the package's files as its tarball unpacked them
/// ([`PackageDirectory::Published`]): a `node_modules/` in it holds the
/// dependencies the package bundles, which count as the package's code.
///
/// Reads within [`ScanLimits::INSTALL`]: a larger source file is sampled at
/// each end, and files past the package limits are skipped. Test files are
/// read, and their tags are reported apart unless the manifest runs or
/// exports them.
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
    let files = collect_package_files(package_dir);

    // Use rayon for parallel scanning on packages with many files (20+).
    // Smaller packages don't benefit from thread pool overhead.
    let mut analyzer = if files.sources.len() >= 20 {
        analyze_files_parallel(package_dir, &files.sources)
    } else {
        analyze_files_sequential(package_dir, &files.sources)
    };
    for artifact in &files.native_artifacts {
        analyzer.note_entry(artifact.strip_prefix(package_dir).unwrap_or(artifact));
    }
    let source_scan_ns = source_scan_start.elapsed().as_nanos();
    let manifest = read_package_manifest(package_dir);

    (
        analyzer.finish(manifest.as_deref()),
        PackageAnalysisTimings { source_scan_ns },
    )
}

/// What a package directory an analysis walks holds besides the package's
/// own files.
#[derive(Clone, Copy, Debug)]
pub enum PackageDirectory<'a> {
    /// The package's files as its tarball unpacked them. A `node_modules/`
    /// among them holds the dependencies the package bundles, which the
    /// analysis reads as the package's code.
    Published,
    /// A package a project installed. The linker may have nested other
    /// packages in its `node_modules/`, at these package-relative
    /// directories. The analysis leaves them out, so their code counts once,
    /// as theirs, and reads the rest of `node_modules/` as bundled.
    Installed(&'a [std::path::PathBuf]),
    /// A local directory a project depends on. Its `node_modules/`
    /// directories hold its own installs, packages in their own right that
    /// a project doesn't get from it, so the analysis reads none of them.
    LocalSource,
}

/// The packages a linker nested in each installed package directory, from
/// the directories of every installed package: `node_modules/bar` under
/// `kit` for a package at `kit/node_modules/bar`. A directory's entry is
/// what its [`PackageDirectory::Installed`] takes.
pub fn nested_packages<'a>(
    package_dirs: impl IntoIterator<Item = &'a Path>,
) -> HashMap<&'a Path, Vec<std::path::PathBuf>> {
    let mut nested: HashMap<&Path, Vec<std::path::PathBuf>> = HashMap::new();
    for package_dir in package_dirs {
        let Some(parent) = package_dir
            .ancestors()
            .skip(1)
            .find(|ancestor| ancestor.file_name() == Some(std::ffi::OsStr::new("node_modules")))
            .and_then(Path::parent)
        else {
            continue;
        };
        if let Ok(relative) = package_dir.strip_prefix(parent) {
            nested
                .entry(parent)
                .or_default()
                .push(relative.to_path_buf());
        }
    }
    nested
}

impl PackageDirectory<'_> {
    /// Whether the analysis walks into the package-relative directory
    /// `relative`, whose parent it already walks.
    fn walks_into(self, relative: &Path) -> bool {
        PackageAnalyzer::should_scan_directory(relative)
            && match self {
                Self::Published => true,
                Self::Installed(nested) => !nested.iter().any(|package| package == relative),
                Self::LocalSource => {
                    relative.file_name() != Some(std::ffi::OsStr::new("node_modules"))
                }
            }
    }
}

/// Analyze a package through an already-open directory capability.
///
/// The descriptor pins the selected package root. Every nested directory and
/// file is opened without following links, so concurrent path replacement
/// cannot redirect the scan outside that root.
pub fn analyze_package_from_open_dir(
    package_dir: &cap_std::fs::Dir,
    contents: PackageDirectory<'_>,
) -> PackageAnalysis {
    analyze_package_from_open_dir_with_fingerprint(package_dir, contents).0
}

/// Analyze a descriptor-rooted package and fingerprint the exact bytes used.
///
/// The fingerprint is unavailable when discovery or any selected input read
/// fails. The returned partial analysis remains usable for the current
/// command, but callers must not persist it for later reuse.
pub fn analyze_package_from_open_dir_with_fingerprint(
    package_dir: &cap_std::fs::Dir,
    contents: PackageDirectory<'_>,
) -> (PackageAnalysis, Option<String>) {
    let mut source_files = CapSourceFiles::new();
    let mut native_artifacts = Vec::new();
    let mut discovery_limit_reached = false;
    let discovery_complete = collect_cap_fingerprint_files(
        package_dir,
        Path::new(""),
        contents,
        &mut source_files,
        &mut native_artifacts,
        &mut discovery_limit_reached,
    )
    .is_ok();
    native_artifacts.sort_unstable();
    let source_files = source_files.into_sorted_vec();
    let (source_files, prefix_limit_reached) = cap_scan_prefix(&source_files);
    let (mut analyzer, mut fingerprint, runtime_limit_reached) =
        analyze_cap_files_with_fingerprint(package_dir, source_files, discovery_complete);
    analyzer.limit_reached |=
        discovery_limit_reached || prefix_limit_reached || runtime_limit_reached;
    if let Some(hasher) = fingerprint.as_mut() {
        hash_native_artifacts(hasher, &native_artifacts);
    }
    for artifact in &native_artifacts {
        analyzer.note_entry(artifact);
    }

    let manifest = match read_package_manifest_from_open_dir(package_dir) {
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
            Some(content)
        }
        Ok(None) | Err(_) => None,
    };
    let mut analysis = analyzer.finish(manifest.as_deref());
    if analysis.meta.input_incomplete {
        fingerprint = None;
    }
    analysis.meta.input_incomplete = fingerprint.is_none();
    let fingerprint = fingerprint.map(|mut hasher| {
        hasher.update(b"limits\0");
        hasher.update([u8::from(
            discovery_limit_reached || prefix_limit_reached || runtime_limit_reached,
        )]);
        format!("sha256-{}", hex::encode(hasher.finalize()))
    });
    (analysis, fingerprint)
}

/// Hash the exact package inputs that can affect behavioral analysis.
///
/// The walk uses the same path, file-count, file-size, and total-byte policy as
/// [`analyze_package_from_open_dir`] given the same `contents`. Symlinks and
/// ignored paths do not participate because the analyzer does not read them.
/// Any unexpected I/O error prevents cache reuse instead of authenticating a
/// partial snapshot.
pub fn package_input_fingerprint_from_open_dir(
    package_dir: &cap_std::fs::Dir,
    contents: PackageDirectory<'_>,
) -> std::io::Result<String> {
    let mut files = CapSourceFiles::new();
    let mut native_artifacts = Vec::new();
    let mut discovery_limit_reached = false;
    collect_cap_fingerprint_files(
        package_dir,
        Path::new(""),
        contents,
        &mut files,
        &mut native_artifacts,
        &mut discovery_limit_reached,
    )?;
    native_artifacts.sort_unstable();
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
    hash_native_artifacts(&mut hasher, &native_artifacts);

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

    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
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
    contents: PackageDirectory<'_>,
    files: &mut CapSourceFiles,
    native_artifacts: &mut Vec<std::path::PathBuf>,
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
            if !contents.walks_into(&relative) {
                continue;
            }
            let child = directory.open_dir_nofollow(&name)?;
            collect_cap_fingerprint_files(
                &child,
                &relative,
                contents,
                files,
                native_artifacts,
                limit_reached,
            )?;
        } else if metadata.is_file() {
            if PackageAnalyzer::should_scan(&relative, metadata.len()) {
                let candidate = CapSourceFile {
                    path: relative,
                    size: metadata.len(),
                };
                *limit_reached |= files.insert(candidate);
            } else if PackageAnalyzer::is_native_artifact(&relative) {
                if native_artifacts.len() < MAX_FILES_PER_PACKAGE {
                    native_artifacts.push(relative);
                } else {
                    *limit_reached = true;
                }
            }
        }
    }
    Ok(())
}

/// Adds the native artifacts a package ships to its input fingerprint: they
/// set `nativeBindings` without being read.
fn hash_native_artifacts(hasher: &mut Sha256, artifacts: &[std::path::PathBuf]) {
    for artifact in artifacts {
        let path = artifact.as_os_str().as_encoded_bytes();
        hasher.update(b"native\0");
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path);
    }
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
        read_oversized_source_sample_from_open_file(
            &mut file,
            source_file.size,
            OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES,
        )?
    } else {
        lpm_common::read_file_capped_from_open_file(file, &source_file.path, MAX_FILE_SIZE)
            .map_err(std::io::Error::other)?
            .0
    };
    let analysis = source_file
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|_filename| {
            if source_file.size > MAX_FILE_SIZE {
                analyze_oversized_source_sample(
                    &source_file.path,
                    source_file.size,
                    &bytes,
                    comment_buf,
                )
            } else {
                analyze_bytes_with_scratch(
                    &path_to_slash(&source_file.path),
                    &bytes,
                    comment_buf,
                    true,
                )
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
) -> (PackageAnalyzer, Option<Sha256>, bool) {
    use rayon::prelude::*;

    let mut analyzer = PackageAnalyzer::new();
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
                analyzer.merge(result);
            }
        }
        if runtime_limit_reached {
            break;
        }
    }
    analyzer.limit_reached |= runtime_limit_reached;
    (analyzer, fingerprint, runtime_limit_reached)
}

fn digest_cap_source_file(file: cap_std::fs::File, size: u64) -> std::io::Result<(u64, [u8; 32])> {
    if size > MAX_FILE_SIZE {
        let mut file = file.into_std();
        let sample = read_oversized_source_sample_from_open_file(
            &mut file,
            size,
            OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES,
        )?;
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
    /// The file's package-relative path, with `/` separators.
    pub path: String,
    pub evidence: Vec<SourceEvidence>,
    pub source: SourceTags,
    pub supply_chain: SupplyChainTags,
    pub url_domains: Vec<String>,
    pub total_code_lines: usize,
    pub total_export_count: usize,
    pub files_scanned: usize,
    pub unparsed_files: usize,
    pub bytes_scanned: u64,
    pub oversized_source_files: Vec<OversizedSourceFileEvidence>,
    /// `eval()` and `new Function()` calls the eval tag found.
    pub eval_calls: usize,
}

/// Analyze a single file. Returns None if the file should be skipped.
fn analyze_single_file(
    package_dir: &Path,
    file_path: &std::path::PathBuf,
    comment_buf: &mut Vec<u8>,
) -> Option<FileAnalysisResult> {
    let file_size = std::fs::metadata(file_path).ok()?.len();
    let relative_path = file_path
        .strip_prefix(package_dir)
        .unwrap_or(file_path.as_path());

    if file_size > MAX_FILE_SIZE {
        return Some(analyze_oversized_source_file(
            relative_path,
            file_path,
            file_size,
            OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES,
            comment_buf,
        ));
    }

    let raw_content = std::fs::read(file_path).ok()?;
    Some(analyze_bytes_with_scratch(
        &path_to_slash(relative_path),
        &raw_content,
        comment_buf,
        true,
    ))
}

/// Core scan pass without the filesystem read — takes the file's
/// package-relative path and raw bytes and returns the same
/// `FileAnalysisResult` as [`analyze_single_file`]. The fused-scan path in
/// `lpm-store` invokes this during tar extraction, using bytes the extractor
/// already had in hand instead of re-reading the file a second time.
///
/// The caller is responsible for:
/// - filtering by extension (`SOURCE_EXTENSIONS`), `.d.ts`/`.map`
///   exclusion, and directory filtering (hidden directories).
///   [`PackageAnalyzer::should_scan`] encodes the current policy.
/// - routing files over the 4 MiB full-scan limit to
///   [`PackageAnalyzer::feed_oversized_source_file`] or another bounded
///   sampling path instead of passing the entire file here.
///
/// Pure function: no I/O; parses bounded source and reuses the comment buffer. Safe to call from any thread, no runtime needed.
pub fn analyze_bytes(filename: &str, raw_content: &[u8]) -> FileAnalysisResult {
    let mut comment_buf = Vec::new();
    analyze_bytes_with_scratch(filename, raw_content, &mut comment_buf, true)
}

fn analyze_bytes_with_scratch(
    filename: &str,
    raw_content: &[u8],
    comment_buf: &mut Vec<u8>,
    complete_input: bool,
) -> FileAnalysisResult {
    let raw_text = String::from_utf8_lossy(raw_content);
    let context = syntax::SourceContext::with_complete_input(
        &raw_text,
        filename,
        comment_buf,
        complete_input,
    );
    let stripped = context.stripped.as_ref();

    let (file_source_tags, mut evidence) =
        source::analyze_source_context_with_evidence(&context, Some(filename));
    let domains = supply_chain::extract_url_domains(stripped);
    let mut file_supply_tags =
        supply_chain::analyze_supply_chain_context(&context, raw_content, !domains.is_empty());
    file_supply_tags.minified |= supply_chain::is_minified_filename(filename);
    supply_chain::append_evidence(&context, filename, &file_supply_tags, &mut evidence);
    let trivial = supply_chain::analyze_trivial(stripped);
    let eval_calls = source::eval_calls(&context);

    FileAnalysisResult {
        path: filename.to_owned(),
        eval_calls,
        evidence,
        source: file_source_tags,
        supply_chain: file_supply_tags,
        url_domains: domains,
        total_code_lines: trivial.total_code_lines,
        total_export_count: trivial.export_count,
        files_scanned: 1,
        unparsed_files: usize::from(
            !context.complete || matches!(raw_text, std::borrow::Cow::Owned(_)),
        ),
        bytes_scanned: raw_content.len() as u64,
        oversized_source_files: Vec::new(),
    }
}

fn analyze_oversized_source_file(
    relative_path: &Path,
    file_path: &Path,
    size: u64,
    sample_bytes: usize,
    comment_buf: &mut Vec<u8>,
) -> FileAnalysisResult {
    let sample = read_oversized_source_sample(file_path, size, sample_bytes).unwrap_or_default();
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
    let path = path_to_slash(relative_path);
    let mut result = if sample.is_empty() {
        FileAnalysisResult {
            path: path.clone(),
            ..FileAnalysisResult::default()
        }
    } else {
        // Disjoint samples cannot establish a data flow between their source ranges.
        analyze_bytes_with_scratch(&path, sample, comment_buf, false)
    };

    result.files_scanned = 0;
    result.bytes_scanned = sample.len() as u64;
    for entry in &mut result.evidence {
        entry.sampled = true;
        entry.line = None;
        entry.column = None;
    }
    result.supply_chain.minified |= supply_chain::is_minified_filename(filename);

    let evidence = OversizedSourceFileEvidence {
        path,
        size_bytes: size,
        sample_bytes_scanned: sample.len() as u64,
        signals: oversized_source_signals(&result.source, &result.supply_chain),
        url_domains: result.url_domains.clone(),
        minified_filename: supply_chain::is_minified_filename(filename),
    };
    result.oversized_source_files = vec![evidence];
    result
}

fn read_oversized_source_sample(
    file_path: &Path,
    size: u64,
    sample_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(file_path)?;
    read_oversized_source_sample_from_open_file(&mut file, size, sample_bytes)
}

fn read_oversized_source_sample_from_open_file(
    file: &mut std::fs::File,
    size: u64,
    sample_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let chunk = sample_bytes.min(size as usize);
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

fn oversized_source_sample_from_bytes(bytes: &[u8], sample_bytes: usize) -> Vec<u8> {
    let chunk = sample_bytes.min(bytes.len());
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
        path: path_to_slash(relative_path),
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
    active_file_tags(source, supply_chain)
        .map(str::to_owned)
        .collect()
}

/// Registry keys of the source and supply-chain tags set, other than
/// `trivial`, which describes a whole package rather than a file.
fn active_file_tags<'t>(
    source: &'t SourceTags,
    supply_chain: &'t SupplyChainTags,
) -> impl Iterator<Item = &'static str> + 't {
    [
        (source.filesystem, "filesystem"),
        (source.network, "network"),
        (source.child_process, "childProcess"),
        (source.environment_vars, "environmentVars"),
        (source.eval, "eval"),
        (source.native_bindings, "nativeBindings"),
        (source.crypto, "crypto"),
        (source.shell, "shell"),
        (source.web_socket, "webSocket"),
        (source.dynamic_require, "dynamicRequire"),
        (supply_chain.obfuscated, "obfuscated"),
        (supply_chain.possible_obfuscation, "possibleObfuscation"),
        (supply_chain.high_entropy_strings, "highEntropyStrings"),
        (supply_chain.minified, "minified"),
        (supply_chain.telemetry, "telemetry"),
        (supply_chain.url_strings, "urlStrings"),
        (supply_chain.protestware, "protestware"),
        (
            supply_chain.credential_exfiltration,
            "credentialExfiltration",
        ),
        (supply_chain.encrypted_execution, "encryptedExecution"),
        (supply_chain.downloaded_execution, "downloadedExecution"),
        (supply_chain.destructive_filesystem, "destructiveFilesystem"),
    ]
    .into_iter()
    .filter_map(|(active, key)| active.then_some(key))
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

/// Sequential file scanning (for packages with < 20 files).
fn analyze_files_sequential(package_dir: &Path, files: &[std::path::PathBuf]) -> PackageAnalyzer {
    let mut analyzer = PackageAnalyzer::new();
    let mut comment_buf = Vec::new();

    for (index, file_path) in files.iter().enumerate() {
        if analyzer.files_scanned >= MAX_FILES_PER_PACKAGE {
            analyzer.skip_remaining(files.len() - index);
            break;
        }
        if let Some(result) = analyze_single_file(package_dir, file_path, &mut comment_buf) {
            if analyzer.bytes_scanned + result.bytes_scanned > MAX_TOTAL_SCAN_BYTES {
                analyzer.skip_remaining(files.len() - index);
                break;
            }
            analyzer.merge(result);
        }
    }

    analyzer
}

/// Parallel file scanning using rayon (for packages with 20+ files).
fn analyze_files_parallel(package_dir: &Path, files: &[std::path::PathBuf]) -> PackageAnalyzer {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let files_scanned = AtomicUsize::new(0);
    let bytes_scanned = AtomicU64::new(0);
    let skipped = AtomicUsize::new(0);

    // Analyze all files in parallel, collecting results
    let results: Vec<FileAnalysisResult> = files
        .par_iter()
        .map_init(Vec::new, |comment_buf, file_path| {
            // Approximate limit checks (may slightly overshoot — acceptable for safety limits)
            if files_scanned.load(Ordering::Relaxed) >= MAX_FILES_PER_PACKAGE
                || bytes_scanned.load(Ordering::Relaxed) > MAX_TOTAL_SCAN_BYTES
            {
                skipped.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            let result = analyze_single_file(package_dir, file_path, comment_buf)?;
            files_scanned.fetch_add(result.files_scanned, Ordering::Relaxed);
            bytes_scanned.fetch_add(result.bytes_scanned, Ordering::Relaxed);
            Some(result)
        })
        .filter_map(|result| result)
        .collect();

    let mut analyzer = PackageAnalyzer::new();
    for result in results {
        analyzer.merge(result);
    }
    let skipped = skipped.into_inner();
    if skipped > 0
        || files_scanned.load(Ordering::Relaxed) >= MAX_FILES_PER_PACKAGE
        || bytes_scanned.load(Ordering::Relaxed) > MAX_TOTAL_SCAN_BYTES
    {
        analyzer.skip_remaining(skipped);
    }
    analyzer
}

/// The files of a package directory the analysis reads or notes.
#[derive(Default)]
struct PackageFiles {
    sources: Vec<std::path::PathBuf>,
    native_artifacts: Vec<std::path::PathBuf>,
}

/// Collect source files and native artifacts from a package directory,
/// bundled dependencies included.
///
/// Skips hidden files/directories, `.d.ts` files, and `.map` files.
/// Returns paths sorted for deterministic analysis order.
fn collect_package_files(dir: &Path) -> PackageFiles {
    let mut files = PackageFiles::default();
    collect_source_files_recursive(dir, &mut files);
    files.sources.sort();
    files.native_artifacts.sort();
    files.native_artifacts.truncate(MAX_FILES_PER_PACKAGE);
    files
}

fn collect_source_files_recursive(dir: &Path, files: &mut PackageFiles) {
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
            collect_source_files_recursive(&path, files);
            continue;
        }

        if roles::is_native_artifact_path(&name_str) {
            files.native_artifacts.push(path);
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

        files.sources.push(path);
    }
}

/// The `package.json` of a package directory, within the configuration file
/// size cap.
fn read_package_manifest(package_dir: &Path) -> Option<Vec<u8>> {
    lpm_common::read_text_file_capped(
        &package_dir.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .ok()
    .map(String::into_bytes)
}

/// A package manifest's tags, and the scripts and entry points that decide
/// whether a test file runs.
fn read_manifest(content: &[u8]) -> Option<(ManifestTags, roles::EntryReferences)> {
    let content = std::str::from_utf8(content).ok()?;
    let parsed: serde_json::Value =
        serde_json::from_str(content.trim_start_matches('\u{feff}')).ok()?;
    parsed.as_object()?;
    let references = roles::EntryReferences::from_manifest(&parsed);

    // A string, or the deprecated `{ "type": "MIT", "url": ... }` object;
    // `licence` is the common misspelling.
    let license_field = |field: &str| {
        let value = parsed.get(field)?;
        value
            .as_str()
            .or_else(|| value.get("type").and_then(|kind| kind.as_str()))
    };
    let license = license_field("license").or_else(|| license_field("licence"));
    let private_package = parsed
        .get("private")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let dependencies = parse_deps_map(parsed.get("dependencies"));
    let optional_dependencies = parse_deps_map(parsed.get("optionalDependencies"));

    Some((
        manifest::analyze_manifest_with_privacy(
            license,
            private_package,
            dependencies.as_ref(),
            optional_dependencies.as_ref(),
        ),
        references,
    ))
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
/// and every entry's path through [`PackageAnalyzer::note_entry`] while the
/// extractor walks the archive. Once extraction completes,
/// [`PackageAnalyzer::finalize`] reads `package.json` from the now-written
/// staging directory, runs the manifest-level analysis, and returns a
/// [`PackageAnalysis`] identical to [`analyze_package`]'s.
///
/// A test file's tags wait for the manifest: they count as the package's own
/// when its lifecycle scripts or entry points name the file, and are
/// reported as tests-only otherwise.
#[derive(Debug)]
pub struct PackageAnalyzer {
    limits: ScanLimits,
    runtime: TagTotals,
    tests: Vec<FileAnalysisResult>,
    native_artifacts: Vec<String>,
    oversized_source_files: Vec<OversizedSourceFileEvidence>,
    files_scanned: usize,
    unparsed_files: usize,
    bytes_scanned: u64,
    sampled_files: usize,
    skipped_files: usize,
    limit_reached: bool,
    source_scan_ns: u128,
}

impl Default for PackageAnalyzer {
    fn default() -> Self {
        Self::with_limits(ScanLimits::INSTALL)
    }
}

/// The tags of a set of files, and which files showed each.
#[derive(Debug, Default)]
struct TagTotals {
    evidence: Vec<SourceEvidence>,
    source: SourceTags,
    supply_chain: SupplyChainTags,
    url_domains: Vec<String>,
    total_code_lines: usize,
    total_export_count: usize,
    files_scanned: usize,
    eval_calls: usize,
    files: BTreeMap<&'static str, TagFileSet>,
}

/// The first paths, in path order, of the files that showed a tag, and how
/// many did.
#[derive(Debug, Default)]
struct TagFileSet {
    first: Vec<String>,
    count: usize,
}

impl TagFileSet {
    fn add(&mut self, path: &str) {
        self.count += 1;
        let position = self
            .first
            .partition_point(|current| current.as_str() < path);
        if position < MAX_TAG_FILES {
            self.first.truncate(MAX_TAG_FILES - 1);
            self.first.insert(position, path.to_owned());
        }
    }
}

impl TagTotals {
    fn add(&mut self, result: FileAnalysisResult) {
        for key in active_file_tags(&result.source, &result.supply_chain) {
            self.files.entry(key).or_default().add(&result.path);
        }
        evidence::merge_evidence(&mut self.evidence, result.evidence);
        self.source = source::merge_source_tags(&self.source, &result.source);
        self.supply_chain =
            supply_chain::merge_supply_chain_tags(&self.supply_chain, &result.supply_chain);
        self.url_domains.extend(result.url_domains);
        self.total_code_lines += result.total_code_lines;
        self.total_export_count += result.total_export_count;
        self.files_scanned += result.files_scanned;
        self.eval_calls += result.eval_calls;
    }

    fn add_native_artifact(&mut self, path: &str) {
        self.source.native_bindings = true;
        self.files.entry("nativeBindings").or_default().add(path);
        let reason = if path.ends_with(".node") {
            "The package ships a compiled native addon."
        } else {
            "node-gyp builds a native addon from this file when the package is installed."
        };
        evidence::merge_evidence(
            &mut self.evidence,
            vec![SourceEvidence::new("native", path, reason)],
        );
    }

    fn keys(&self) -> impl Iterator<Item = &'static str> + '_ {
        active_file_tags(&self.source, &self.supply_chain)
    }
}

impl PackageAnalyzer {
    /// Create an empty analyzer with [`ScanLimits::INSTALL`]. Cheap — no
    /// allocations beyond defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty analyzer that reads within `limits`.
    pub fn with_limits(limits: ScanLimits) -> Self {
        Self {
            limits,
            runtime: TagTotals::default(),
            tests: Vec::new(),
            native_artifacts: Vec::new(),
            oversized_source_files: Vec::new(),
            files_scanned: 0,
            unparsed_files: 0,
            bytes_scanned: 0,
            sampled_files: 0,
            skipped_files: 0,
            limit_reached: false,
            source_scan_ns: 0,
        }
    }

    /// Does this tar entry qualify for source analysis?
    ///
    /// Returns `true` iff:
    /// - Extension is in `SOURCE_EXTENSIONS` (js/mjs/cjs/ts/mts/cts/jsx/tsx)
    /// - Filename is not `.d.ts` / `.d.mts` / `.d.cts` / `.map`
    /// - No path component starts with `.` (hidden files/dirs)
    ///
    /// A file under `node_modules/` qualifies: in a tarball, it's a
    /// dependency the package bundles.
    ///
    /// The size cap is intentionally NOT checked here: oversized files still
    /// need lightweight metadata via [`PackageAnalyzer::feed_oversized_source_file`].
    ///
    /// Mirrors the `collect_source_files_recursive` filter exactly so the
    /// fused path scans the same set of files as the two-pass path.
    pub fn should_scan(relative_path: &Path, _size: u64) -> bool {
        if !Self::in_scanned_tree(relative_path) {
            return false;
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

    /// Whether an entry is a native addon the analysis notes: a `.node` file
    /// or `binding.gyp` outside the trees it skips.
    pub fn is_native_artifact(relative_path: &Path) -> bool {
        Self::in_scanned_tree(relative_path)
            && roles::is_native_artifact_path(&path_to_slash(relative_path))
    }

    fn in_scanned_tree(relative_path: &Path) -> bool {
        relative_path.components().all(|component| match component {
            std::path::Component::Normal(name) => !name.as_encoded_bytes().starts_with(b"."),
            _ => true,
        })
    }

    fn should_scan_directory(relative_path: &Path) -> bool {
        relative_path.components().all(|component| {
            let std::path::Component::Normal(name) = component else {
                return false;
            };
            !name.as_encoded_bytes().starts_with(b".")
        })
    }

    /// Should the extractor buffer this source entry for full byte-level scanning?
    pub fn should_buffer_source(relative_path: &Path, size: u64) -> bool {
        Self::should_scan(relative_path, size) && size <= MAX_FILE_SIZE
    }

    /// Note one entry of the package, of any kind. A native addon among them
    /// sets `nativeBindings`.
    pub fn note_entry(&mut self, relative_path: &Path) {
        if Self::is_native_artifact(relative_path) {
            self.note_native_artifact(path_to_slash(relative_path));
        }
    }

    /// Note a native addon at `path`, wherever it is in the package.
    pub(crate) fn note_native_artifact(&mut self, path: String) {
        if self.native_artifacts.len() < self.limits.files {
            self.native_artifacts.push(path);
        } else {
            self.limit_reached = true;
        }
    }

    /// Feed one scannable file's bytes. Respects the package limits — once
    /// one is hit, later files are skipped and `limit_reached` is set.
    pub fn feed(&mut self, relative_path: &Path, bytes: &[u8]) {
        if self.files_scanned >= self.limits.files {
            self.skip_remaining(1);
            return;
        }
        if bytes.len() as u64 > self.limits.full_file_bytes {
            let sample = oversized_source_sample_from_bytes(bytes, self.limits.sample_bytes);
            self.feed_sample(relative_path, bytes.len() as u64, &sample);
            return;
        }

        if self.bytes_scanned + bytes.len() as u64 > self.limits.total_bytes {
            self.skip_remaining(1);
            return;
        }

        let scan_start = std::time::Instant::now();
        let result = analyze_bytes(&path_to_slash(relative_path), bytes);
        self.merge(result);
        self.source_scan_ns = self
            .source_scan_ns
            .saturating_add(scan_start.elapsed().as_nanos());
    }

    /// Feed the ends of a source file of `size` bytes too large to read whole:
    /// `sample` is its first bytes, a line break, and its last bytes.
    pub fn feed_sample(&mut self, relative_path: &Path, size: u64, sample: &[u8]) {
        let scan_start = std::time::Instant::now();
        let mut comment_buf = Vec::new();
        let result = analyze_oversized_source_sample(relative_path, size, sample, &mut comment_buf);
        self.merge_within_limits(result);
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
        let result = analyze_oversized_source_file(
            relative_path,
            full_path,
            size,
            self.limits.sample_bytes,
            &mut comment_buf,
        );
        self.merge_within_limits(result);
        self.source_scan_ns = self
            .source_scan_ns
            .saturating_add(scan_start.elapsed().as_nanos());
    }

    /// Record an "oversized minified" file without reading its bytes.
    /// Used by the fused path for files that pass the
    /// `should_scan` extension test but exceed 4 MiB and match a minified
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
            self.merge_within_limits(result);
            self.source_scan_ns = self
                .source_scan_ns
                .saturating_add(scan_start.elapsed().as_nanos());
        }
    }

    /// Return the accumulated time spent running source detectors.
    pub fn source_scan_ns(&self) -> u128 {
        self.source_scan_ns
    }

    fn skip_remaining(&mut self, files: usize) {
        self.skipped_files += files;
        self.limit_reached = true;
    }

    fn merge_within_limits(&mut self, result: FileAnalysisResult) {
        if self.bytes_scanned + result.bytes_scanned > self.limits.total_bytes {
            self.skip_remaining(1);
            return;
        }
        self.merge(result);
    }

    fn merge(&mut self, mut result: FileAnalysisResult) {
        let oversized = std::mem::take(&mut result.oversized_source_files);
        if !oversized.is_empty() {
            self.sampled_files += 1;
            self.limit_reached = true;
            extend_oversized_source_files(&mut self.oversized_source_files, oversized);
        }
        self.files_scanned += result.files_scanned;
        self.unparsed_files += result.unparsed_files;
        self.bytes_scanned += result.bytes_scanned;
        if roles::is_test_path(&result.path) {
            self.tests.push(result);
        } else {
            self.runtime.add(result);
        }
    }

    /// Complete the analysis: read the package manifest from disk,
    /// deduplicate URL domains, compute the package-level `trivial`
    /// tag, and build the final [`PackageAnalysis`]. Mirrors the tail
    /// of [`analyze_package`] exactly so outputs are byte-for-byte
    /// compatible with the two-pass path.
    pub fn finalize(self, package_dir: &Path) -> PackageAnalysis {
        let manifest = read_package_manifest(package_dir);
        self.finish(manifest.as_deref())
    }

    /// Complete the analysis with the package's `package.json` bytes, or
    /// `None` when it has none or it couldn't be read.
    pub fn finish(mut self, manifest: Option<&[u8]>) -> PackageAnalysis {
        let (manifest_tags, references) = match manifest.and_then(read_manifest) {
            Some((tags, references)) => (Some(tags), references),
            None => (None, roles::EntryReferences::default()),
        };

        let mut tests = TagTotals::default();
        for result in std::mem::take(&mut self.tests) {
            if references.name(&result.path) {
                self.runtime.add(result);
            } else {
                tests.add(result);
            }
        }
        for path in std::mem::take(&mut self.native_artifacts) {
            if roles::is_test_path(&path) && !references.name(&path) {
                tests.add_native_artifact(&path);
            } else {
                self.runtime.add_native_artifact(&path);
            }
        }

        let mut runtime = self.runtime;
        if runtime.files_scanned > 0 {
            runtime.supply_chain.trivial =
                runtime.total_code_lines < 10 && runtime.total_export_count <= 1;
        }
        let runtime_keys: std::collections::BTreeSet<&'static str> = runtime.keys().collect();
        let mut test_only_tags: Vec<&'static str> = tests
            .keys()
            .filter(|key| {
                !runtime_keys.contains(key)
                    && !(*key == "possibleObfuscation" && runtime_keys.contains("obfuscated"))
            })
            .collect();
        test_only_tags.sort_unstable();

        let mut tag_files = BTreeMap::new();
        for key in runtime_keys.iter().chain(&test_only_tags) {
            let ran = runtime.files.remove(key).unwrap_or_default();
            let tested = tests.files.remove(key).unwrap_or_default();
            let mut files = ran.first;
            files.extend(tested.first.into_iter().take(MAX_TAG_FILES - files.len()));
            tag_files.insert(
                (*key).to_owned(),
                TagFiles {
                    files,
                    file_count: ran.count + tested.count,
                    tests_only: ran.count == 0,
                },
            );
        }

        let mut evidence = runtime.evidence;
        let runtime_rules: std::collections::HashSet<String> =
            evidence.iter().map(|entry| entry.rule_id.clone()).collect();
        evidence::merge_evidence(
            &mut evidence,
            tests
                .evidence
                .into_iter()
                .filter(|entry| !runtime_rules.contains(&entry.rule_id))
                .collect(),
        );

        let mut url_domains = runtime.url_domains;
        url_domains.sort_unstable();
        url_domains.dedup();

        PackageAnalysis {
            version: SCHEMA_VERSION,
            analyzed_at: chrono::Utc::now().to_rfc3339(),
            source: runtime.source,
            supply_chain: runtime.supply_chain,
            meta: AnalysisMeta {
                evidence,
                files_scanned: self.files_scanned,
                unparsed_files: self.unparsed_files,
                input_incomplete: manifest_tags.is_none(),
                bytes_scanned: self.bytes_scanned,
                limit_reached: self.limit_reached,
                url_domains,
                oversized_source_files: self.oversized_source_files,
                sampled_files: self.sampled_files,
                skipped_files: self.skipped_files,
                tag_files,
                test_only_tags: test_only_tags.into_iter().map(str::to_owned).collect(),
                eval_calls: runtime.eval_calls,
            },
            manifest: manifest_tags.unwrap_or_default(),
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
		|| analysis.supply_chain.credential_exfiltration
        || analysis.supply_chain.encrypted_execution
        || analysis.supply_chain.downloaded_execution
        || analysis.supply_chain.destructive_filesystem
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

    #[test]
    fn analyze_package_reads_deprecated_license_object() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"test","license":{"type":"MIT","url":"https://example.com"}}"#,
                ),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(!analysis.manifest.no_license);
        assert!(!analysis.manifest.custom_license);
    }

    #[test]
    fn analyze_package_custom_license() {
        let dir = tempfile::tempdir().unwrap();
        create_test_package(
            dir.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"test","license":"SEE LICENSE IN LICENSE.md"}"#,
                ),
                ("index.js", "module.exports = 42"),
            ],
        );

        let analysis = analyze_package(dir.path());
        assert!(analysis.manifest.custom_license);
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
        let capability_analysis =
            analyze_package_from_open_dir(&directory, PackageDirectory::Published);
        let mut path_json = serde_json::to_value(path_analysis).unwrap();
        let mut capability_json = serde_json::to_value(capability_analysis).unwrap();
        path_json["analyzedAt"] = serde_json::Value::Null;
        capability_json["analyzedAt"] = serde_json::Value::Null;

        assert_eq!(capability_json, path_json);
    }

    #[test]
    fn reviewed_source_controls_preserve_capabilities_and_critical_patterns() {
        let controls: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/source-capabilities.json"
        ))
        .unwrap();
        for control in controls.as_array().unwrap() {
            let result = analyze_bytes("index.js", control["source"].as_str().unwrap().as_bytes());
            let actual =
                serde_json::json!({"source": result.source, "supplyChain": result.supply_chain});
            for (group, fields) in control["expected"].as_object().unwrap() {
                for (field, expected) in fields.as_object().unwrap() {
                    assert_eq!(
                        &actual[group][field], expected,
                        "{}: {group}.{field}",
                        control["name"]
                    );
                }
            }
        }
    }

    #[test]
    fn streaming_scans_and_serialized_cache_retain_relative_evidence() {
        let package = tempfile::tempdir().unwrap();
        let files = [
            (
                "package.json",
                r#"{"name":"evidence","version":"1.0.0","license":"MIT"}"#,
            ),
            (
                "lib/compile.js",
                "export const compile = input => eval(input);",
            ),
            ("examples/network.js", "fetch(endpoint);"),
        ];
        create_test_package(package.path(), &files);
        let direct = analyze_package(package.path());
        let mut streaming = PackageAnalyzer::new();
        for (path, source) in files.iter().rev() {
            if PackageAnalyzer::should_scan(Path::new(path), source.len() as u64) {
                streaming.feed(Path::new(path), source.as_bytes());
            }
        }
        let streamed = streaming.finalize(package.path());
        let cached: PackageAnalysis =
            serde_json::from_slice(&serde_json::to_vec(&streamed).unwrap()).unwrap();
        assert_eq!(direct.meta.evidence, cached.meta.evidence);
        let eval = cached
            .meta
            .evidence
            .iter()
            .find(|e| e.rule_id == "eval")
            .unwrap();
        assert_eq!(eval.path, "lib/compile.js");
        assert_eq!(eval.line, Some(1));
        let network = cached
            .meta
            .evidence
            .iter()
            .find(|e| e.rule_id == "network")
            .unwrap();
        assert_eq!(network.file_context, "test-or-example");
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
            analyze_package_from_open_dir_with_fingerprint(&directory, PackageDirectory::Published);
        let standalone_fingerprint =
            package_input_fingerprint_from_open_dir(&directory, PackageDirectory::Published)
                .unwrap();

        assert!(analysis.source.eval);
        assert_eq!(
            fused_fingerprint.as_deref(),
            Some(standalone_fingerprint.as_str())
        );

        fs::write(package.path().join("index.js"), "module.exports = 1;\n").unwrap();
        assert_ne!(
            package_input_fingerprint_from_open_dir(&directory, PackageDirectory::Published)
                .unwrap(),
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

        let error =
            package_input_fingerprint_from_open_dir(&directory, PackageDirectory::Published)
                .unwrap_err();

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
        assert_eq!(selected.len(), 12);
        assert_eq!(selected[0].path, Path::new("source-00.js"));
        assert_eq!(selected[11].path, Path::new("source-11.js"));
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
        let mut native_artifacts = Vec::new();
        let mut limit_reached = false;

        collect_cap_fingerprint_files(
            &directory,
            Path::new(""),
            PackageDirectory::Published,
            &mut files,
            &mut native_artifacts,
            &mut limit_reached,
        )
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

        let analysis = analyze_package_from_open_dir(&directory, PackageDirectory::Published);

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

        let analysis = analyze_package_from_open_dir(&directory, PackageDirectory::Published);

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
    fn reads_the_dependencies_a_package_bundles() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","bundleDependencies":["helper"]}"#,
            ),
            ("index.js", br#"module.exports = require("helper")"#),
            ("node_modules/helper/index.js", b"eval(payload)"),
            (
                "node_modules/helper/test/run.js",
                b"require('child_process')",
            ),
            (
                "node_modules/helper/node_modules/inner/addon.node",
                b"\x7fELF",
            ),
        ]);

        assert!(analysis.source.eval);
        assert!(analysis.source.native_bindings);
        assert_eq!(analysis.meta.test_only_tags, ["childProcess"]);
        assert_eq!(analysis.meta.files_scanned, 3);
        assert_eq!(
            analysis.meta.tag_files["eval"].files,
            ["node_modules/helper/index.js"]
        );
    }

    #[test]
    fn an_installed_package_leaves_out_the_packages_nested_in_it() {
        let package = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[
                ("package.json", r#"{"name":"kit","license":"MIT"}"#),
                ("index.js", r#"module.exports = require("helper")"#),
                ("node_modules/helper/index.js", "eval(payload)"),
                ("node_modules/bar/index.js", "require('child_process')"),
                ("node_modules/@scope/baz/index.js", "fetch(url)"),
            ],
        );
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();
        let nested = [
            std::path::PathBuf::from("node_modules/bar"),
            std::path::PathBuf::from("node_modules/@scope/baz"),
        ];
        let installed = PackageDirectory::Installed(&nested);

        let (analysis, fingerprint) =
            analyze_package_from_open_dir_with_fingerprint(&directory, installed);

        assert!(analysis.source.eval);
        assert!(!analysis.source.child_process);
        assert!(!analysis.source.network);
        assert_eq!(analysis.meta.files_scanned, 2);
        let fingerprint = fingerprint.unwrap();
        assert_eq!(
            package_input_fingerprint_from_open_dir(&directory, installed).unwrap(),
            fingerprint
        );
        fs::write(
            package.path().join("node_modules/bar/index.js"),
            "require('net')",
        )
        .unwrap();
        assert_eq!(
            package_input_fingerprint_from_open_dir(&directory, installed).unwrap(),
            fingerprint
        );
        fs::write(
            package.path().join("node_modules/helper/index.js"),
            "eval(other)",
        )
        .unwrap();
        assert_ne!(
            package_input_fingerprint_from_open_dir(&directory, installed).unwrap(),
            fingerprint
        );
    }

    #[test]
    fn finds_the_packages_nested_in_each_installed_package() {
        let dirs = [
            "/p/node_modules/kit",
            "/p/node_modules/kit/node_modules/bar",
            "/p/node_modules/kit/node_modules/@scope/baz",
            "/p/node_modules/kit/node_modules/bar/node_modules/deep",
            "/p/node_modules/other",
        ]
        .map(Path::new);

        let nested = nested_packages(dirs);

        assert_eq!(
            nested[Path::new("/p/node_modules/kit")],
            [
                Path::new("node_modules/bar"),
                Path::new("node_modules/@scope/baz")
            ]
        );
        assert_eq!(
            nested[Path::new("/p/node_modules/kit/node_modules/bar")],
            [Path::new("node_modules/deep")]
        );
        assert!(!nested.contains_key(Path::new("/p/node_modules/other")));
    }

    #[test]
    fn a_local_source_leaves_out_its_own_installs() {
        let package = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[
                ("package.json", r#"{"name":"kit","license":"MIT"}"#),
                ("index.js", "module.exports = 1"),
                ("node_modules/tool/index.js", "eval(payload)"),
                ("packages/inner/node_modules/tool/index.js", "eval(payload)"),
            ],
        );
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        let analysis = analyze_package_from_open_dir(&directory, PackageDirectory::LocalSource);

        assert!(!analysis.source.eval);
        assert_eq!(analysis.meta.files_scanned, 1);
    }

    #[test]
    fn only_dependencies_a_consumer_installs_set_the_dependency_tags() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","dependencies":{"left":"^1.0.0"},
                    "devDependencies":{"tape":"*","fixture":"github:owner/fixture","mirror":"http://example.com/m.tgz"}}"#,
            ),
            ("index.js", b"module.exports = 1"),
        ]);

        assert!(!analysis.manifest.wildcard_dependency);
        assert!(!analysis.manifest.git_dependency);
        assert!(!analysis.manifest.http_dependency);
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
        assert!(!analysis.meta.evidence.is_empty());
        assert!(
            analysis
                .meta
                .evidence
                .iter()
                .all(|entry| entry.sampled && entry.line.is_none() && entry.column.is_none())
        );
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
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"native-pkg","version":"1.0.0","license":"MIT"}"#,
            ),
            (
                "index.js",
                b"const binding = require('./build/Release/addon.node')",
            ),
            ("build/Release/addon.node", b"\x7fELF\x02\x01\x01\0"),
        ]);
        assert!(analysis.source.native_bindings);
        assert_eq!(
            analysis.meta.tag_files["nativeBindings"],
            TagFiles {
                files: vec!["build/Release/addon.node".to_owned()],
                file_count: 1,
                tests_only: false,
            }
        );
        assert!(
            analysis
                .meta
                .evidence
                .iter()
                .any(|entry| entry.rule_id == "native" && entry.path == "build/Release/addon.node")
        );
    }

    #[test]
    fn binding_gyp_is_a_native_addon_and_a_mentioned_addon_is_not() {
        let gyp = analyze_every_way(&[
            ("package.json", br#"{"name":"gyp","license":"MIT"}"#),
            ("binding.gyp", br#"{"targets":[]}"#),
        ]);
        assert!(gyp.source.native_bindings);

        let mentioned = analyze_every_way(&[
            ("package.json", br#"{"name":"plain","license":"MIT"}"#),
            ("server.js", br#"module.exports = require("./server.node")"#),
            ("server.node.js", b"module.exports = 1"),
        ]);
        assert!(!mentioned.source.native_bindings);
        assert!(!mentioned.meta.tag_files.contains_key("nativeBindings"));
    }

    // ── Files each tag came from, and tags only tests showed ──

    /// Analyzes a package by its directory path, through an open directory,
    /// and streamed as an extraction does, and checks the three agree.
    fn analyze_every_way(files: &[(&str, &[u8])]) -> PackageAnalysis {
        let package = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let file_path = package.path().join(path);
            fs::create_dir_all(file_path.parent().unwrap()).unwrap();
            fs::write(&file_path, content).unwrap();
        }
        let by_path = analyze_package(package.path());
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();
        let by_capability = analyze_package_from_open_dir(&directory, PackageDirectory::Published);
        let mut streaming = PackageAnalyzer::new();
        for (path, content) in files.iter().rev() {
            let path = Path::new(path);
            streaming.note_entry(path);
            if PackageAnalyzer::should_buffer_source(path, content.len() as u64) {
                streaming.feed(path, content);
            }
        }
        let streamed = streaming.finalize(package.path());

        let comparable = |analysis: &PackageAnalysis| {
            let mut value = serde_json::to_value(analysis).unwrap();
            value["analyzedAt"] = serde_json::Value::Null;
            value
        };
        assert_eq!(comparable(&by_capability), comparable(&by_path));
        assert_eq!(comparable(&streamed), comparable(&by_path));
        by_path
    }

    #[test]
    fn names_the_files_each_tag_came_from_runtime_files_first() {
        let mut files: Vec<(String, &[u8])> =
            vec![("test/eval.test.js".to_owned(), b"eval(a)".as_slice())];
        files.extend((0..6).map(|index| (format!("dist/chunk-{index}.js"), b"eval(b)".as_slice())));
        let files: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(path, content)| (path.as_str(), *content))
            .collect();

        let analysis = analyze_every_way(&files);

        assert_eq!(
            analysis.meta.tag_files["eval"],
            TagFiles {
                files: (0..5)
                    .map(|index| format!("dist/chunk-{index}.js"))
                    .collect(),
                file_count: 7,
                tests_only: false,
            }
        );
    }

    #[test]
    fn a_tag_only_test_files_showed_is_tests_only_not_runtime() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            (
                "src/__tests__/run.test.ts",
                br#"require("child_process").spawn("node")"#,
            ),
            ("src/e.test.js", b"eval(code)"),
            ("lib/index.js", b"module.exports = fetch(url)"),
        ]);

        assert!(!analysis.source.child_process);
        assert!(!analysis.source.eval);
        assert!(analysis.source.network);
        assert_eq!(analysis.meta.test_only_tags, ["childProcess", "eval"]);
        assert_eq!(
            analysis.meta.tag_files["childProcess"],
            TagFiles {
                files: vec!["src/__tests__/run.test.ts".to_owned()],
                file_count: 1,
                tests_only: true,
            }
        );
        assert!(!analysis.meta.tag_files["network"].tests_only);
        assert_eq!(analysis.meta.eval_calls, 0);
    }

    #[test]
    fn a_test_file_the_package_runs_on_install_or_exports_counts_as_runtime() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","scripts":{"postinstall":"node test/setup","test":"node tests/other.js"},"exports":{"./client":{"default":"./tests/client.js"}}}"#,
            ),
            ("test/setup.js", br#"require("child_process").spawn("node")"#),
            ("tests/client.js", b"module.exports = fetch(url)"),
            ("tests/other.js", b"eval(code)"),
        ]);

        assert!(analysis.source.child_process);
        assert!(analysis.source.network);
        assert!(!analysis.source.eval);
        assert_eq!(analysis.meta.test_only_tags, ["eval"]);
        assert!(!analysis.meta.tag_files["childProcess"].tests_only);
    }

    #[test]
    fn counts_the_eval_calls_of_runtime_files() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            (
                "index.js",
                br#"var u="https://example.test/";eval(u);new Function("return 1")()
const usage = "eval(x)" /* eval(y) */"#,
            ),
            ("unparsed.js", br#"const usage = "eval(x)"; )("#),
            ("test/eval.test.js", b"eval(a); eval(b)"),
        ]);

        assert_eq!(analysis.meta.eval_calls, 3);
    }

    #[test]
    fn trivial_counts_only_runtime_code() {
        let tests = (0..20)
            .map(|index| format!("it('case {index}', () => {{}})"))
            .collect::<Vec<_>>()
            .join("\n");
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", b"module.exports = (a, b) => a + b"),
            ("test/index.test.js", tests.as_bytes()),
        ]);

        assert!(analysis.supply_chain.trivial);
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
