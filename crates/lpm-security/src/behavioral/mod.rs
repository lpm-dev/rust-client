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
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
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
///
/// The files the package runs and its test files are read within budgets of
/// their own, so tests can never crowd out the code the package runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanLimits {
    /// A source file up to this size is read whole.
    pub full_file_bytes: u64,
    /// Bytes read from each end of a larger source file.
    pub sample_bytes: usize,
    /// Bytes read from the files the package runs before the rest of them
    /// are skipped.
    pub total_bytes: u64,
    /// Files the package runs read, whole or sampled, before the rest are
    /// skipped.
    pub files: usize,
    /// Bytes read from test files before the rest of them are skipped.
    pub test_bytes: u64,
    /// Test files read, whole or sampled, before the rest are skipped.
    pub test_files: usize,
}

impl ScanLimits {
    /// Installs and audits, which analyze every package of a project.
    pub const INSTALL: Self = Self {
        full_file_bytes: MAX_FILE_SIZE,
        sample_bytes: OVERSIZED_SOURCE_SAMPLE_CHUNK_BYTES,
        total_bytes: MAX_TOTAL_SCAN_BYTES,
        files: MAX_FILES_PER_PACKAGE,
        test_bytes: MAX_TOTAL_SCAN_BYTES / 4,
        test_files: MAX_FILES_PER_PACKAGE / 4,
    };

    /// A registry's analysis of one published release.
    pub const REGISTRY: Self = Self {
        full_file_bytes: 8 * 1024 * 1024,
        sample_bytes: 1024 * 1024,
        total_bytes: 64 * 1024 * 1024,
        files: MAX_FILES_PER_PACKAGE,
        test_bytes: 16 * 1024 * 1024,
        test_files: MAX_FILES_PER_PACKAGE / 4,
    };

    /// Bytes a scan reads of a source file of `size` bytes: all of it, or
    /// each end and the line break that joins them.
    fn read_bytes(self, size: u64) -> u64 {
        if size <= self.full_file_bytes {
            return size;
        }
        let chunk = (self.sample_bytes as u64).min(size);
        if size.saturating_sub(chunk) > chunk {
            chunk.saturating_mul(2).saturating_add(1)
        } else {
            size
        }
    }
}

/// What a scan has read of its [`ScanLimits`] budgets.
#[derive(Clone, Copy, Debug)]
struct ScanBudget {
    limits: ScanLimits,
    files: usize,
    bytes: u64,
    test_files: usize,
    test_bytes: u64,
}

impl ScanBudget {
    fn new(limits: ScanLimits) -> Self {
        Self {
            limits,
            files: 0,
            bytes: 0,
            test_files: 0,
            test_bytes: 0,
        }
    }

    /// Takes a file that reads `bytes` from the tests' or the package's
    /// budget, or says it doesn't fit.
    fn admit(&mut self, test: bool, bytes: u64) -> bool {
        let (files, used, max_files, max_bytes) = if test {
            (
                &mut self.test_files,
                &mut self.test_bytes,
                self.limits.test_files,
                self.limits.test_bytes,
            )
        } else {
            (
                &mut self.files,
                &mut self.bytes,
                self.limits.files,
                self.limits.total_bytes,
            )
        };
        if *files >= max_files || used.saturating_add(bytes) > max_bytes {
            return false;
        }
        *files += 1;
        *used += bytes;
        true
    }
}

/// What a source file is to its package. A directory scan reads its files
/// in this order: the package's own code, the dependencies it bundles, and
/// then its tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FileRole {
    Own,
    Bundled,
    Test,
}

impl FileRole {
    fn of(relative_path: &Path) -> Self {
        if roles::is_test_path(&path_to_slash(relative_path)) {
            Self::Test
        } else if relative_path
            .components()
            .any(|component| component.as_os_str() == "node_modules")
        {
            Self::Bundled
        } else {
            Self::Own
        }
    }

    #[inline]
    fn is_test(self) -> bool {
        self == Self::Test
    }
}

/// A source file a directory scan found. The derived order is read order.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SourceFile {
    role: FileRole,
    path: std::path::PathBuf,
    size: u64,
}

/// The source files a directory walk found: for the package's code and for
/// its tests, the first in read order up to the budget's file limit, and how
/// many files there were in all.
struct SourceFiles {
    runtime: FirstFiles,
    tests: FirstFiles,
    found: usize,
}

impl SourceFiles {
    fn new(limits: ScanLimits) -> Self {
        Self {
            runtime: FirstFiles::new(limits.files),
            tests: FirstFiles::new(limits.test_files),
            found: 0,
        }
    }

    /// Adds a file the walk found, and says whether a file limit left a file
    /// out.
    fn insert(&mut self, file: SourceFile) -> bool {
        self.found += 1;
        if file.role.is_test() {
            self.tests.insert(file)
        } else {
            self.runtime.insert(file)
        }
    }

    /// The files kept, in read order, and how many the walk found.
    fn into_read_order(self) -> (Vec<SourceFile>, usize) {
        let mut files = self.runtime.into_sorted_vec();
        files.extend(self.tests.into_sorted_vec());
        (files, self.found)
    }
}

/// The first `max` files in read order of the files inserted.
struct FirstFiles {
    max: usize,
    files: FirstFilesState,
}

enum FirstFilesState {
    Collecting(Vec<SourceFile>),
    Limited(BinaryHeap<SourceFile>),
}

impl FirstFiles {
    fn new(max: usize) -> Self {
        Self {
            max,
            files: FirstFilesState::Collecting(Vec::new()),
        }
    }

    /// Adds a file, and says whether the limit left a file out.
    fn insert(&mut self, candidate: SourceFile) -> bool {
        match &mut self.files {
            FirstFilesState::Collecting(files) if files.len() < self.max => {
                files.push(candidate);
                false
            }
            FirstFilesState::Collecting(files) => {
                let mut limited = BinaryHeap::from(std::mem::take(files));
                keep_if_earlier(&mut limited, candidate);
                self.files = FirstFilesState::Limited(limited);
                true
            }
            FirstFilesState::Limited(files) => {
                keep_if_earlier(files, candidate);
                true
            }
        }
    }

    fn into_sorted_vec(self) -> Vec<SourceFile> {
        match self.files {
            FirstFilesState::Collecting(mut files) => {
                files.sort_unstable();
                files
            }
            FirstFilesState::Limited(files) => files.into_sorted_vec(),
        }
    }
}

fn keep_if_earlier(files: &mut BinaryHeap<SourceFile>, candidate: SourceFile) {
    if files.peek().is_some_and(|latest| candidate < *latest) {
        files.pop();
        files.push(candidate);
    }
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
    /// The calls that run code from a string in the files the tag fields
    /// cover, as the eval tag finds them: `eval()`, `new Function()`, the
    /// `vm` module's script runs, and indirect `eval`.
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
    let limits = ScanLimits::INSTALL;
    let mut sources = SourceFiles::new(limits);
    let mut native_artifacts = Vec::new();
    collect_source_files_recursive(
        package_dir,
        Path::new(""),
        &mut sources,
        &mut native_artifacts,
    );
    let (candidates, found) = sources.into_read_order();
    let mut budget = ScanBudget::new(limits);
    let admitted: Vec<SourceFile> = candidates
        .into_iter()
        .filter(|file| budget.admit(file.role.is_test(), limits.read_bytes(file.size)))
        .collect();

    // Smaller packages don't benefit from thread pool overhead.
    let results: Vec<Option<FileAnalysisResult>> = if admitted.len() >= 20 {
        use rayon::prelude::*;
        admitted
            .par_iter()
            .map_init(Vec::new, |comment_buf, file| {
                analyze_source_file(package_dir, file, limits, comment_buf)
            })
            .collect()
    } else {
        let mut comment_buf = Vec::new();
        admitted
            .iter()
            .map(|file| analyze_source_file(package_dir, file, limits, &mut comment_buf))
            .collect()
    };

    let mut analyzer = PackageAnalyzer::with_limits(limits);
    for result in results.into_iter().flatten() {
        analyzer.merge(result);
    }
    analyzer.skip(found - admitted.len());
    native_artifacts.sort_unstable();
    if native_artifacts.len() > MAX_FILES_PER_PACKAGE {
        native_artifacts.truncate(MAX_FILES_PER_PACKAGE);
        analyzer.limit_reached = true;
    }
    for artifact in &native_artifacts {
        analyzer.note_entry(artifact);
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
    /// The package's files as its tarball unpacked them, hidden files
    /// included. A `node_modules/` among them holds the dependencies the
    /// package bundles, which the analysis reads as the package's code.
    Published,
    /// A package a project installed. The linker may have nested other
    /// packages in its `node_modules/`, at these package-relative
    /// directories. The analysis leaves them out, so their code counts once,
    /// as theirs, and reads the rest of `node_modules/` as bundled.
    Installed(&'a [std::path::PathBuf]),
    /// A local directory a project depends on. Its `node_modules/`
    /// directories hold its own installs, packages in their own right that
    /// a project doesn't get from it, so the analysis reads none of them.
    /// Its hidden files are its tooling and caches; the analysis reads only
    /// those its lifecycle scripts or entry points name.
    LocalSource,
}

/// The packages a linker nested in each installed package directory, from
/// the directories of every installed package: `node_modules/bar` under
/// `kit` for a package at `kit/node_modules/bar`. A package is nested in the
/// closest installed package around it, even through a directory that isn't
/// one, such as a dependency `kit` bundles. A directory's entry is what its
/// [`PackageDirectory::Installed`] takes.
pub fn nested_packages<'a>(
    package_dirs: impl IntoIterator<Item = &'a Path>,
) -> HashMap<&'a Path, Vec<std::path::PathBuf>> {
    let package_dirs: Vec<&Path> = package_dirs.into_iter().collect();
    let installed: std::collections::HashSet<&Path> = package_dirs.iter().copied().collect();
    let mut nested: HashMap<&Path, Vec<std::path::PathBuf>> = HashMap::new();
    for package_dir in package_dirs {
        let Some(owner) = package_dir
            .ancestors()
            .skip(1)
            .find_map(|ancestor| installed.get(ancestor).copied())
        else {
            continue;
        };
        if let Ok(relative) = package_dir.strip_prefix(owner) {
            nested
                .entry(owner)
                .or_default()
                .push(relative.to_path_buf());
        }
    }
    nested
}

/// What a directory walk reads of a [`PackageDirectory`].
///
/// A published or installed package's files are read as an npm client
/// unpacks them, hidden files and `.git` included, except, in an installed
/// package, the packages the linker nested in it. A local source's
/// `node_modules/` holds its own installs, and its hidden files and `.git`
/// are its tooling and caches (`.next`, `.turbo`): only the hidden files its
/// lifecycle scripts or entry points name are read.
struct WalkRules<'a> {
    contents: PackageDirectory<'a>,
    /// An installed package's nested packages, which the walk checks every
    /// entry against.
    nested: HashSet<&'a Path>,
    /// A local source's lifecycle scripts and entry points.
    local_entries: Option<roles::EntryReferences>,
}

impl<'a> WalkRules<'a> {
    fn new(package_dir: &cap_std::fs::Dir, contents: PackageDirectory<'a>) -> Self {
        let local_entries = matches!(contents, PackageDirectory::LocalSource)
            .then(|| read_package_manifest_from_open_dir(package_dir))
            .and_then(|manifest| manifest.ok().flatten())
            .and_then(|(_, content)| read_manifest(&content))
            .map(|(_, references)| references);
        let nested = match contents {
            PackageDirectory::Installed(nested) => nested.iter().map(PathBuf::as_path).collect(),
            _ => HashSet::new(),
        };
        Self {
            contents,
            nested,
            local_entries,
        }
    }

    /// Whether the walk reads the package-relative entry `relative`, a
    /// directory to walk into or a file, whose parent it already walks.
    fn reads(&self, relative: &Path, directory: bool) -> bool {
        let Some(name) = relative.file_name() else {
            return false;
        };
        match self.contents {
            PackageDirectory::Published => true,
            PackageDirectory::Installed(_) => !self.nested.contains(relative),
            PackageDirectory::LocalSource => {
                if name == "node_modules" || is_git_dir_component(name) {
                    return false;
                }
                let hidden = relative
                    .components()
                    .any(|component| component.as_os_str().as_encoded_bytes().starts_with(b"."));
                if !hidden {
                    return true;
                }
                let Some(entries) = &self.local_entries else {
                    return false;
                };
                let path = path_to_slash(relative);
                if directory {
                    entries.mention_directory(&path)
                } else {
                    entries.name(&path)
                }
            }
        }
    }
}

/// Whether a path component is one git reads as `.git`
/// ([`lpm_common::names::is_git_dir_name`]).
fn is_git_dir_component(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(lpm_common::names::is_git_dir_name)
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
    let limits = ScanLimits::INSTALL;
    let mut sources = SourceFiles::new(limits);
    let mut native_artifacts = Vec::new();
    let mut discovery_limit_reached = false;
    let rules = WalkRules::new(package_dir, contents);
    let discovery_complete = collect_cap_fingerprint_files(
        package_dir,
        Path::new(""),
        &rules,
        &mut sources,
        &mut native_artifacts,
        &mut discovery_limit_reached,
    )
    .is_ok();
    native_artifacts.sort_unstable();
    let (candidates, found) = sources.into_read_order();
    let candidate_count = candidates.len();
    let (mut analyzer, mut fingerprint, over_budget) =
        analyze_cap_files_with_fingerprint(package_dir, candidates, limits, discovery_complete);
    let skipped = found - candidate_count + over_budget;
    analyzer.skip(skipped);
    let limit_reached = discovery_limit_reached || skipped > 0;
    analyzer.limit_reached |= limit_reached;
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
        hasher.update([u8::from(limit_reached)]);
        format!("sha256-{}", hex::encode(hasher.finalize()))
    });
    (analysis, fingerprint)
}

/// Hash the exact package inputs that can affect behavioral analysis.
///
/// The walk uses the same path, file-count, file-size, and byte budgets as
/// [`analyze_package_from_open_dir`] given the same `contents`. Symlinks and
/// ignored paths do not participate because the analyzer does not read them.
/// Any unexpected I/O error prevents cache reuse instead of authenticating a
/// partial snapshot.
pub fn package_input_fingerprint_from_open_dir(
    package_dir: &cap_std::fs::Dir,
    contents: PackageDirectory<'_>,
) -> std::io::Result<String> {
    let limits = ScanLimits::INSTALL;
    let mut sources = SourceFiles::new(limits);
    let mut native_artifacts = Vec::new();
    let mut discovery_limit_reached = false;
    let rules = WalkRules::new(package_dir, contents);
    collect_cap_fingerprint_files(
        package_dir,
        Path::new(""),
        &rules,
        &mut sources,
        &mut native_artifacts,
        &mut discovery_limit_reached,
    )?;
    native_artifacts.sort_unstable();
    let (candidates, found) = sources.into_read_order();

    let mut hasher = new_fingerprint_hasher();
    let mut budget = ScanBudget::new(limits);
    let mut over_budget = 0usize;
    for source_file in &candidates {
        let (file, size) = open_cap_source_file(package_dir, &source_file.path)?;
        if !budget.admit(source_file.role.is_test(), limits.read_bytes(size)) {
            over_budget += 1;
            continue;
        }
        let (bytes_read, content_digest) = digest_cap_source_file(file, size, limits)?;
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

    let skipped = found - candidates.len() + over_budget;
    hasher.update(b"limits\0");
    hasher.update([u8::from(discovery_limit_reached || skipped > 0)]);

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
    rules: &WalkRules<'_>,
    files: &mut SourceFiles,
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
        if !rules.reads(&relative, metadata.is_dir()) {
            continue;
        }
        if metadata.is_dir() {
            let child = directory.open_dir_nofollow(&name)?;
            collect_cap_fingerprint_files(
                &child,
                &relative,
                rules,
                files,
                native_artifacts,
                limit_reached,
            )?;
        } else if metadata.is_file() {
            if PackageAnalyzer::should_scan(&relative, metadata.len()) {
                let candidate = SourceFile {
                    role: FileRole::of(&relative),
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
    limits: ScanLimits,
    comment_buf: &mut Vec<u8>,
) -> std::io::Result<ScannedCapSourceFile> {
    let mut file = source_file.file.into_std();
    let sampled = source_file.size > limits.full_file_bytes;
    let bytes = if sampled {
        read_oversized_source_sample_from_open_file(
            &mut file,
            source_file.size,
            limits.sample_bytes,
        )?
    } else {
        lpm_common::read_file_capped_from_open_file(file, &source_file.path, limits.full_file_bytes)
            .map_err(std::io::Error::other)?
            .0
    };
    let analysis = source_file
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|_| {
            if sampled {
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

/// Reads the `files` a directory walk kept, in read order, within the
/// package's budgets. Returns the analysis, the input fingerprint unless a
/// read failed, and how many files the budgets left unread.
fn analyze_cap_files_with_fingerprint(
    package_dir: &cap_std::fs::Dir,
    files: Vec<SourceFile>,
    limits: ScanLimits,
    fingerprint_valid: bool,
) -> (PackageAnalyzer, Option<Sha256>, usize) {
    use rayon::prelude::*;

    let mut analyzer = PackageAnalyzer::with_limits(limits);
    let mut fingerprint = fingerprint_valid.then(new_fingerprint_hasher);
    let mut budget = ScanBudget::new(limits);
    let mut over_budget = 0usize;
    let batch_size = if files.len() >= 20 {
        rayon::current_num_threads()
            .saturating_mul(2)
            .clamp(20, 128)
    } else {
        files.len().max(1)
    };

    let mut files = files.into_iter().peekable();
    while files.peek().is_some() {
        let mut opened = Vec::with_capacity(batch_size);
        for source_file in files.by_ref().take(batch_size) {
            let (file, size) = match open_cap_source_file(package_dir, &source_file.path) {
                Ok(opened) => opened,
                Err(_) => {
                    fingerprint = None;
                    continue;
                }
            };
            if !budget.admit(source_file.role.is_test(), limits.read_bytes(size)) {
                over_budget += 1;
                continue;
            }
            opened.push(OpenCapSourceFile {
                path: source_file.path,
                file,
                size,
            });
        }

        let results: Vec<std::io::Result<ScannedCapSourceFile>> = if opened.len() >= 20 {
            opened
                .into_par_iter()
                .map_init(Vec::new, |comment_buf, source_file| {
                    analyze_open_cap_source_file(source_file, limits, comment_buf)
                })
                .collect()
        } else {
            let mut comment_buf = Vec::new();
            opened
                .into_iter()
                .map(|source_file| {
                    analyze_open_cap_source_file(source_file, limits, &mut comment_buf)
                })
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
    }
    (analyzer, fingerprint, over_budget)
}

fn digest_cap_source_file(
    file: cap_std::fs::File,
    size: u64,
    limits: ScanLimits,
) -> std::io::Result<(u64, [u8; 32])> {
    if size > limits.full_file_bytes {
        let mut file = file.into_std();
        let sample =
            read_oversized_source_sample_from_open_file(&mut file, size, limits.sample_bytes)?;
        return Ok((sample.len() as u64, Sha256::digest(&sample).into()));
    }

    let mut file = file
        .into_std()
        .take(limits.full_file_bytes.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes_read = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        if bytes_read > limits.full_file_bytes {
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
    /// Calls that run code from a string, as the eval tag finds them.
    pub eval_calls: usize,
}

/// Analyze one source file a directory walk found. `None` when it can't be
/// read.
fn analyze_source_file(
    package_dir: &Path,
    file: &SourceFile,
    limits: ScanLimits,
    comment_buf: &mut Vec<u8>,
) -> Option<FileAnalysisResult> {
    let full_path = package_dir.join(&file.path);
    if file.size > limits.full_file_bytes {
        return Some(analyze_oversized_source_file(
            &file.path,
            &full_path,
            file.size,
            limits.sample_bytes,
            comment_buf,
        ));
    }

    let raw_content = lpm_common::read_file_capped(&full_path, limits.full_file_bytes).ok()?;
    Some(analyze_bytes_with_scratch(
        &path_to_slash(&file.path),
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
/// - filtering by extension (`SOURCE_EXTENSIONS`) and `.d.ts`/`.map`
///   exclusion.
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

/// The first and last `sample_bytes` of a file of `size` bytes, joined by a
/// line break, or the whole file when the two would meet.
fn read_oversized_source_sample_from_open_file(
    file: &mut std::fs::File,
    size: u64,
    sample_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let chunk = (sample_bytes as u64).min(size);
    let tail_start = size.saturating_sub(chunk);
    if tail_start <= chunk {
        let mut whole = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
        read_file_chunk(file, 0, size, &mut whole)?;
        return Ok(whole);
    }
    let mut sample = Vec::with_capacity(sample_bytes.saturating_mul(2).saturating_add(1));
    read_file_chunk(file, 0, chunk, &mut sample)?;
    sample.push(b'\n');
    read_file_chunk(file, tail_start, chunk, &mut sample)?;
    Ok(sample)
}

fn read_file_chunk(
    file: &mut std::fs::File,
    start: u64,
    max_bytes: u64,
    out: &mut Vec<u8>,
) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(start))?;
    file.by_ref().take(max_bytes).read_to_end(out)?;
    Ok(())
}

/// [`read_oversized_source_sample_from_open_file`] for bytes in memory.
fn oversized_source_sample_from_bytes(bytes: &[u8], sample_bytes: usize) -> Vec<u8> {
    let chunk = sample_bytes.min(bytes.len());
    let tail_start = bytes.len() - chunk;
    if tail_start <= chunk {
        return bytes.to_vec();
    }
    let mut sample = Vec::with_capacity(chunk * 2 + 1);
    sample.extend_from_slice(&bytes[..chunk]);
    sample.push(b'\n');
    sample.extend_from_slice(&bytes[tail_start..]);
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

/// Collect the source files and native artifacts of a package directory as
/// its tarball unpacked them ([`PackageDirectory::Published`]), bundled
/// dependencies and hidden files included, as package-relative paths.
///
/// Skips symlinks, declaration files, and source maps.
fn collect_source_files_recursive(
    package_dir: &Path,
    relative_dir: &Path,
    files: &mut SourceFiles,
    native_artifacts: &mut Vec<std::path::PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(package_dir.join(relative_dir)) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if lpm_common::is_symlink_or_junction(&metadata) {
            continue;
        }
        let relative = relative_dir.join(&name);
        if metadata.is_dir() {
            collect_source_files_recursive(package_dir, &relative, files, native_artifacts);
        } else if !metadata.is_file() {
            continue;
        } else if PackageAnalyzer::should_scan(&relative, metadata.len()) {
            files.insert(SourceFile {
                role: FileRole::of(&relative),
                path: relative,
                size: metadata.len(),
            });
        } else if PackageAnalyzer::is_native_artifact(&relative) {
            native_artifacts.push(relative);
        }
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
    budget: ScanBudget,
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
            budget: ScanBudget::new(limits),
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
    ///
    /// Hidden files qualify, as an npm client unpacks them. A file under
    /// `node_modules/` qualifies: in a tarball, it's a dependency the
    /// package bundles. Which directories a scan walks is the walk's
    /// decision ([`PackageDirectory`]).
    ///
    /// The size cap is intentionally NOT checked here: oversized files still
    /// need lightweight metadata via [`PackageAnalyzer::feed_oversized_source_file`].
    ///
    /// Mirrors the `collect_source_files_recursive` filter exactly so the
    /// fused path scans the same set of files as the two-pass path.
    pub fn should_scan(relative_path: &Path, _size: u64) -> bool {
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
    /// or `binding.gyp`.
    #[inline]
    pub fn is_native_artifact(relative_path: &Path) -> bool {
        relative_path
            .file_name()
            .is_some_and(|name| roles::is_native_artifact_name(name.as_encoded_bytes()))
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
        if self.native_artifacts.len() < self.budget.limits.files {
            self.native_artifacts.push(path);
        } else {
            self.limit_reached = true;
        }
    }

    /// Feed one scannable file's bytes. A file past its budget, the tests'
    /// or the package's, is skipped and sets `limit_reached`.
    pub fn feed(&mut self, relative_path: &Path, bytes: &[u8]) {
        let limits = self.budget.limits;
        let size = bytes.len() as u64;
        if size > limits.full_file_bytes {
            if self.admit(relative_path, limits.read_bytes(size)) {
                let sample = oversized_source_sample_from_bytes(bytes, limits.sample_bytes);
                self.analyze_sample(relative_path, size, &sample);
            }
            return;
        }
        let path = path_to_slash(relative_path);
        if !self
            .budget
            .admit(roles::is_test_path(&path), bytes.len() as u64)
        {
            self.skip(1);
            return;
        }

        let scan_start = std::time::Instant::now();
        let result = analyze_bytes(&path, bytes);
        self.merge(result);
        self.note_scan_time(scan_start);
    }

    /// Feed the ends of a source file of `size` bytes too large to read whole:
    /// `sample` is its first bytes, a line break, and its last bytes.
    pub fn feed_sample(&mut self, relative_path: &Path, size: u64, sample: &[u8]) {
        if self.admit(relative_path, sample.len() as u64) {
            self.analyze_sample(relative_path, size, sample);
        }
    }

    fn analyze_sample(&mut self, relative_path: &Path, size: u64, sample: &[u8]) {
        let scan_start = std::time::Instant::now();
        let mut comment_buf = Vec::new();
        let result = analyze_oversized_source_sample(relative_path, size, sample, &mut comment_buf);
        self.merge(result);
        self.note_scan_time(scan_start);
    }

    /// Sample an oversized source file from disk after extraction.
    pub fn feed_oversized_source_file(
        &mut self,
        relative_path: &Path,
        full_path: &Path,
        size: u64,
    ) {
        let limits = self.budget.limits;
        if !Self::should_scan(relative_path, size)
            || size <= limits.full_file_bytes
            || !self.admit(relative_path, limits.read_bytes(size))
        {
            return;
        }
        let scan_start = std::time::Instant::now();
        let mut comment_buf = Vec::new();
        let result = analyze_oversized_source_file(
            relative_path,
            full_path,
            size,
            limits.sample_bytes,
            &mut comment_buf,
        );
        self.merge(result);
        self.note_scan_time(scan_start);
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
        if supply_chain::is_minified_filename(&filename) && self.admit(relative_path, 0) {
            let scan_start = std::time::Instant::now();
            let result = oversized_minified_result(relative_path, size);
            self.merge(result);
            self.note_scan_time(scan_start);
        }
    }

    /// Return the accumulated time spent running source detectors.
    pub fn source_scan_ns(&self) -> u128 {
        self.source_scan_ns
    }

    /// Takes a file at `relative_path` that reads `bytes` from its budget,
    /// or skips it.
    fn admit(&mut self, relative_path: &Path, bytes: u64) -> bool {
        let admitted = self
            .budget
            .admit(roles::is_test_path(&path_to_slash(relative_path)), bytes);
        if !admitted {
            self.skip(1);
        }
        admitted
    }

    /// Counts `files` a budget left unread.
    fn skip(&mut self, files: usize) {
        if files > 0 {
            self.skipped_files += files;
            self.limit_reached = true;
        }
    }

    fn note_scan_time(&mut self, scan_start: std::time::Instant) {
        self.source_scan_ns = self
            .source_scan_ns
            .saturating_add(scan_start.elapsed().as_nanos());
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
        let test_results = std::mem::take(&mut self.tests);
        let native_artifacts = std::mem::take(&mut self.native_artifacts);
        let test_addons: Vec<&str> = native_artifacts
            .iter()
            .map(String::as_str)
            .filter(|path| roles::is_test_path(path))
            .collect();
        let queried: Vec<&str> = test_results
            .iter()
            .map(|result| result.path.as_str())
            .chain(test_addons.iter().copied())
            .collect();
        let named = references.names(&queried);
        let (named_results, named_addons) = named.split_at(test_results.len());
        let named_addons: HashMap<&str, bool> = test_addons
            .iter()
            .copied()
            .zip(named_addons.iter().copied())
            .collect();
        for (result, named) in test_results.into_iter().zip(named_results.iter().copied()) {
            if named {
                self.runtime.add(result);
            } else {
                tests.add(result);
            }
        }
        for path in &native_artifacts {
            if named_addons.get(path.as_str()) == Some(&false) {
                tests.add_native_artifact(path);
            } else {
                self.runtime.add_native_artifact(path);
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
    fn package_budget_admits_files_in_read_order_until_its_bytes_run_out() {
        let limits = ScanLimits::INSTALL;
        let mut budget = ScanBudget::new(limits);

        let admitted = (0..30)
            .filter(|_| budget.admit(false, limits.read_bytes(MAX_FILE_SIZE)))
            .count();

        assert_eq!(admitted, 12);
        assert!(budget.admit(false, 1024));
        assert!(budget.admit(true, MAX_FILE_SIZE));
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
        let mut files = SourceFiles::new(ScanLimits::INSTALL);
        let mut native_artifacts = Vec::new();
        let mut limit_reached = false;

        collect_cap_fingerprint_files(
            &directory,
            Path::new(""),
            &WalkRules::new(&directory, PackageDirectory::Published),
            &mut files,
            &mut native_artifacts,
            &mut limit_reached,
        )
        .unwrap();
        let (files, found) = files.into_read_order();

        assert!(limit_reached);
        assert_eq!(found, MAX_FILES_PER_PACKAGE + 1);
        assert_eq!(files.len(), MAX_FILES_PER_PACKAGE);
        assert_eq!(files.first().unwrap().path, Path::new("source-00000.js"));
        assert_eq!(files.last().unwrap().path, Path::new("source-04999.js"));
    }

    /// A package whose test fixtures alone are larger than the package's
    /// read budget, and whose entry point evaluates code.
    fn package_with_large_test_fixtures() -> tempfile::TempDir {
        let package = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"kit","license":"MIT","main":"lib/index.js"}"#,
                ),
                (
                    "lib/index.js",
                    "module.exports = payload => eval(payload)\n",
                ),
            ],
        );
        fs::create_dir_all(package.path().join("__tests__")).unwrap();
        for index in 0..13 {
            fs::File::create(
                package
                    .path()
                    .join(format!("__tests__/fixture-{index:02}.js")),
            )
            .unwrap()
            .set_len(MAX_FILE_SIZE)
            .unwrap();
        }
        package
    }

    #[test]
    fn test_fixtures_never_crowd_out_the_code_a_package_runs() {
        let package = package_with_large_test_fixtures();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        for analysis in [
            analyze_package(package.path()),
            analyze_package_from_open_dir(&directory, PackageDirectory::Published),
        ] {
            assert!(analysis.source.eval);
            assert_eq!(analysis.meta.tag_files["eval"].files, ["lib/index.js"]);
            assert_eq!(analysis.meta.skipped_files, 10);
            assert!(analysis.meta.limit_reached);
        }
    }

    #[test]
    fn streamed_test_fixtures_never_crowd_out_the_code_a_package_runs() {
        let fixture = vec![b' '; MAX_FILE_SIZE as usize];
        let fixtures_size = MAX_TOTAL_SCAN_BYTES as usize;
        let mut analyzer = PackageAnalyzer::new();
        for (index, start) in (0..fixtures_size).step_by(fixture.len()).enumerate() {
            let size = fixture.len().min(fixtures_size - start);
            analyzer.feed(
                Path::new(&format!("__tests__/fixture-{index:02}.js")),
                &fixture[..size],
            );
        }
        analyzer.feed(
            Path::new("lib/index.js"),
            b"module.exports = payload => eval(payload)",
        );

        let analysis = analyzer.finish(Some(br#"{"name":"kit","license":"MIT"}"#));

        assert!(analysis.source.eval);
        assert_eq!(analysis.meta.skipped_files, 10);
    }

    #[test]
    fn directory_scans_read_own_code_before_bundled_dependencies() {
        let package = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[
                ("package.json", r#"{"name":"kit","license":"MIT"}"#),
                (
                    "src/index.js",
                    "module.exports = payload => eval(payload)\n",
                ),
            ],
        );
        fs::create_dir_all(package.path().join("node_modules/bundled")).unwrap();
        for index in 0..13 {
            fs::File::create(
                package
                    .path()
                    .join(format!("node_modules/bundled/part-{index:02}.js")),
            )
            .unwrap()
            .set_len(MAX_FILE_SIZE)
            .unwrap();
        }

        let analysis = analyze_package(package.path());

        assert!(analysis.source.eval);
        assert_eq!(analysis.meta.skipped_files, 1);
    }

    /// Analyzes `source`, named `filename`, on a thread with the stack a
    /// rayon worker has.
    fn analyze_on_a_worker_stack(filename: &'static str, source: String) -> FileAnalysisResult {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || analyze_bytes(filename, source.as_bytes()))
            .unwrap()
            .join()
            .unwrap()
    }

    #[test]
    fn source_nested_deeper_than_a_worker_stack_is_parsed_on_a_stack_that_fits() {
        for (filename, source) in [
            (
                "index.js",
                format!("x={}eval(y){};", "[".repeat(3_000), "]".repeat(3_000)),
            ),
            ("index.js", format!("x={}eval(y);", "a=>".repeat(2_500))),
            (
                "index.js",
                format!("{}eval(y);", "if(a)x;else ".repeat(3_000)),
            ),
            ("index.js", format!("{}eval(y);", "a:".repeat(5_000))),
            (
                "index.js",
                format!(
                    "{}eval(y){}",
                    "(function(){return ".repeat(1_000),
                    "})()".repeat(1_000)
                ),
            ),
            (
                "index.js",
                format!(
                    "x=`{}${{eval(y)}}{}`;",
                    "${`".repeat(2_000),
                    "`}".repeat(2_000)
                ),
            ),
            (
                "index.ts",
                format!(
                    "let x: {}X{} = eval(y);",
                    "A<".repeat(2_000),
                    ">".repeat(2_000)
                ),
            ),
        ] {
            let result = analyze_on_a_worker_stack(filename, source);
            assert!(result.source.eval);
            assert_eq!(result.unparsed_files, 0);
        }
    }

    #[test]
    fn source_nested_too_deeply_to_parse_is_read_without_parsing() {
        for (filename, source) in [
            (
                "index.js",
                format!("x={}eval(y){};", "[".repeat(100_000), "]".repeat(100_000)),
            ),
            ("index.js", format!("x={}eval(y);", "!".repeat(500_000))),
            ("index.js", format!("x=a{}+eval(y);", ".b".repeat(500_000))),
            ("index.js", format!("{}eval(y);", "a:".repeat(200_000))),
            (
                "index.ts",
                format!(
                    "let x: {}X{} = eval(y);",
                    "A<".repeat(200_000),
                    ">".repeat(200_000)
                ),
            ),
            (
                "index.jsx",
                format!(
                    "x={}{}; eval(y);",
                    "<a>".repeat(200_000),
                    "</a>".repeat(200_000)
                ),
            ),
        ] {
            let result = analyze_on_a_worker_stack(filename, source);
            assert!(result.source.eval);
            assert_eq!(result.unparsed_files, 1);
        }
    }

    fn nested(open: &str, middle: &str, close: &str, depth: usize) -> String {
        let mut source = open.repeat(depth);
        source.push_str(middle);
        source.push_str(&close.repeat(depth));
        source
    }

    #[test]
    fn references_nested_thousands_of_scopes_deep_are_read_without_semantic_analysis() {
        // Semantic analysis looks each reference up in every scope around
        // it: 6,000 nested blocks with a reference in each took seconds.
        let started = std::time::Instant::now();
        for source in [
            nested("{eval(y);", "", "}", 6_000),
            nested("if(y){eval(y);", "", "}", 6_000),
            nested("function f(a=y,b=", "0", "){eval(y)}", 3_000),
        ] {
            let result = analyze_on_a_worker_stack("index.js", source);
            assert!(result.source.eval);
            assert_eq!(result.unparsed_files, 1);
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn var_declarations_nested_thousands_of_scopes_deep_are_read_without_semantic_analysis() {
        // Semantic analysis records each `var` name in every block between
        // it and its function, so names declared a thousand blocks deep
        // cost a thousand map entries each, with no reference to count.
        let vars: String = (0..5_000).map(|i| format!("var x{i};")).collect();
        let nested_vars = format!("{}eval(y);", nested("{", &vars, "}", 1_000));
        let flat = format!("{}eval(y);", "var x;".repeat(nested_vars.len() / 6));
        let started = std::time::Instant::now();
        let flat_result = analyze_on_a_worker_stack("index.js", flat);
        let flat_time = started.elapsed();
        let started = std::time::Instant::now();
        let result = analyze_on_a_worker_stack("index.js", nested_vars);
        let nested_time = started.elapsed();
        assert_eq!(flat_result.unparsed_files, 0);
        assert!(result.source.eval);
        assert_eq!(result.unparsed_files, 1);
        assert!(
            nested_time < flat_time * 5 + std::time::Duration::from_millis(200),
            "nested {nested_time:?}, flat {flat_time:?}"
        );
    }

    #[test]
    fn labelled_jumps_inside_thousands_of_labels_are_read_without_semantic_analysis() {
        // Semantic analysis looks each labelled `break` up in the stack of
        // labels around it.
        let labels: String = (0..4_000).map(|i| format!("a{i}:")).collect();
        let source = format!("{labels}{{{}eval(y);}}", "break a0;".repeat(20_000));
        let flat = format!("{}eval(y);", "x;".repeat(source.len() / 2));
        let started = std::time::Instant::now();
        let flat_result = analyze_on_a_worker_stack("index.js", flat);
        let flat_time = started.elapsed();
        let started = std::time::Instant::now();
        let result = analyze_on_a_worker_stack("index.js", source);
        let labelled_time = started.elapsed();
        assert_eq!(flat_result.unparsed_files, 0);
        assert!(result.source.eval);
        assert_eq!(result.unparsed_files, 1);
        assert!(
            labelled_time < flat_time * 5 + std::time::Duration::from_millis(200),
            "labelled {labelled_time:?}, flat {flat_time:?}"
        );
    }

    #[test]
    fn references_nested_as_deeply_as_real_code_nests_them_are_analyzed() {
        for source in [
            nested("{eval(y);", "", "}", 200),
            nested("function f(a=y,b=", "0", "){eval(y)}", 100),
            "function f(){var a=1;".repeat(50) + &"a;".repeat(20_000) + &"}".repeat(50),
            "function f(){".to_owned()
                + &nested("if(y){", &"var v=eval(y);".repeat(2_000), "}", 6)
                + "}",
        ] {
            let result = analyze_on_a_worker_stack("index.js", source);
            assert!(result.source.eval || result.files_scanned == 1);
            assert_eq!(result.unparsed_files, 0);
        }
    }

    #[test]
    fn arrow_defaults_nested_too_deeply_to_parse_stop_in_one_pass() {
        // A parse that reached the stack floor inside a speculative arrow
        // function parse once read every level back down to the floor:
        // gigabytes of arena memory and seconds for a 100 KB source.
        let source = format!("x={};eval(y);", nested("(a=y,b=", "0", ")=>0", 20_000));
        let started = std::time::Instant::now();
        let result = analyze_on_a_worker_stack("index.js", source);
        assert!(result.source.eval);
        assert_eq!(result.unparsed_files, 1);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_long_expression_chain_is_parsed_whole() {
        let result =
            analyze_on_a_worker_stack("index.js", format!("x=1{}+eval(y);", "+1".repeat(30_000)));

        assert!(result.source.eval);
        assert_eq!(result.unparsed_files, 0);
    }

    #[test]
    fn test_files_are_matched_against_the_manifest_in_one_pass() {
        // Each test file and test-path addon searched every manifest
        // reference for its path: 5,000 addons against a 16 MiB manifest
        // took minutes.
        let manifest = serde_json::to_vec(&serde_json::json!({
            "main": "test/".repeat(200_000),
        }))
        .unwrap();
        let finish = |addons: usize| {
            let mut analyzer = PackageAnalyzer::default();
            for index in 0..addons {
                analyzer.note_native_artifact(format!("test/a{index}.node"));
            }
            let started = std::time::Instant::now();
            let analysis = analyzer.finish(Some(&manifest));
            (started.elapsed(), analysis)
        };
        let (one, _) = finish(1);
        let (many, _) = finish(5_000);
        assert!(
            many < one * 5 + std::time::Duration::from_millis(100),
            "5,000 addons {many:?}, one {one:?}"
        );
    }

    #[test]
    fn samples_cover_a_whole_file_no_larger_than_two_samples() {
        let bytes = b"eval(payload); module.exports = 1;";
        assert_eq!(oversized_source_sample_from_bytes(bytes, 20), bytes);
        let limits = ScanLimits {
            full_file_bytes: 10,
            sample_bytes: 20,
            ..ScanLimits::INSTALL
        };
        assert_eq!(limits.read_bytes(bytes.len() as u64), bytes.len() as u64);

        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), bytes).unwrap();
        let mut opened = fs::File::open(file.path()).unwrap();
        assert_eq!(
            read_oversized_source_sample_from_open_file(&mut opened, bytes.len() as u64, 20)
                .unwrap(),
            bytes
        );
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

    /// A package with code in each kind of hidden place npm unpacks: a
    /// hidden directory its `postinstall` runs, a hidden directory in its
    /// `node_modules/`, `node_modules/.bin`, and `.git`, beside a hidden
    /// build cache nothing names.
    fn package_with_hidden_files() -> tempfile::TempDir {
        let package = tempfile::tempdir().unwrap();
        create_test_package(
            package.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"node .x/run.js && node node_modules/.x/env.js"}}"#,
                ),
                ("index.js", "module.exports = 1\n"),
                (
                    ".x/run.js",
                    "require('child_process').exec(process.argv[2])\n",
                ),
                (
                    "node_modules/.x/env.js",
                    "module.exports = process.env.TOKEN\n",
                ),
                (
                    "node_modules/.bin/tool.js",
                    "fetch('https://tool.example/')\n",
                ),
                (".git/hooks/run.js", "eval(process.argv[2])\n"),
                (".cache/build.js", "require('crypto').randomBytes(16)\n"),
            ],
        );
        package
    }

    #[test]
    fn published_and_installed_packages_read_every_hidden_file_npm_unpacks() {
        let package = package_with_hidden_files();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        for analysis in [
            analyze_package(package.path()),
            analyze_package_from_open_dir(&directory, PackageDirectory::Published),
            analyze_package_from_open_dir(&directory, PackageDirectory::Installed(&[])),
        ] {
            assert!(analysis.source.child_process);
            assert!(analysis.source.environment_vars);
            assert!(analysis.source.network);
            assert!(analysis.source.eval);
            assert!(analysis.source.crypto);
        }
        assert!(PackageAnalyzer::should_scan(
            Path::new(".git/hooks/run.js"),
            1
        ));
    }

    #[test]
    fn a_local_source_reads_only_the_hidden_files_its_scripts_or_entry_points_name() {
        let package = package_with_hidden_files();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        let (analysis, fingerprint) = analyze_package_from_open_dir_with_fingerprint(
            &directory,
            PackageDirectory::LocalSource,
        );

        assert!(analysis.source.child_process);
        assert!(!analysis.source.environment_vars);
        assert!(!analysis.source.network);
        assert!(!analysis.source.eval);
        assert!(!analysis.source.crypto);
        assert_eq!(
            fingerprint,
            Some(
                package_input_fingerprint_from_open_dir(&directory, PackageDirectory::LocalSource)
                    .unwrap()
            )
        );
    }

    #[test]
    fn a_package_nested_inside_a_bundled_dependency_belongs_to_the_installed_package() {
        let dirs = [
            "/p/node_modules/kit",
            "/p/node_modules/kit/node_modules/bundled/node_modules/bar",
        ]
        .map(Path::new);

        let nested = nested_packages(dirs);

        assert_eq!(
            nested[Path::new("/p/node_modules/kit")],
            [Path::new("node_modules/bundled/node_modules/bar")]
        );
        assert_eq!(nested.len(), 1);
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
