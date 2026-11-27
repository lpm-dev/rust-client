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
pub(crate) mod syntax;
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
pub const SCHEMA_VERSION: u32 = 15;

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

/// `package.json` files below a package's root an analysis reads. Past this,
/// what the rest name isn't known, and every test file counts.
const MAX_NESTED_MANIFESTS: usize = 1024;

/// Whether a package-relative path is a `package.json` below the root, in
/// any case: on a case-insensitive file system Node finds `PACKAGE.JSON`.
fn is_nested_manifest(relative_path: &Path) -> bool {
    relative_path.file_name().is_some_and(|name| {
        name.as_encoded_bytes()
            .eq_ignore_ascii_case(b"package.json")
    }) && relative_path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
}

/// How deep serde reads JSON: arrays and objects nested deeper fail to parse.
const MAX_JSON_NESTING: usize = 127;

/// Whether `json` nests arrays and objects deeper than `limit`, scanning it
/// once and skipping strings. It needn't be valid JSON.
fn json_nests_deeper_than(json: &[u8], limit: usize) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in json {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > limit {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Bytes of a file read to find its shebang line: the most any kernel reads
/// for one (Linux reads 256, macOS 512).
const SHEBANG_BYTES: usize = 512;

/// Extensions of files that hold data, documents, styles, media, native code
/// or another language's source and build files, never a script Node runs,
/// whatever their first line says.
const NON_SCRIPT_EXTENSIONS: &[&str] = &[
    "json",
    "map",
    "md",
    "markdown",
    "mdx",
    "txt",
    "rst",
    "adoc",
    "css",
    "scss",
    "sass",
    "less",
    "styl",
    "html",
    "htm",
    "xml",
    "svg",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "avif",
    "ico",
    "bmp",
    "tif",
    "tiff",
    "woff",
    "woff2",
    "ttf",
    "otf",
    "eot",
    "mp3",
    "mp4",
    "wav",
    "ogg",
    "webm",
    "mov",
    "wasm",
    "node",
    "so",
    "dylib",
    "dll",
    "exe",
    "a",
    "lib",
    "o",
    "obj",
    "pdb",
    "zip",
    "gz",
    "tgz",
    "tar",
    "br",
    "zst",
    "xz",
    "bz2",
    "7z",
    "jar",
    "aar",
    "pdf",
    "yml",
    "yaml",
    "toml",
    "ini",
    "csv",
    "tsv",
    "lock",
    "log",
    "flow",
    "snap",
    "proto",
    "graphql",
    "gql",
    "po",
    "mo",
    "pot",
    "properties",
    "pem",
    "crt",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "h",
    "hpp",
    "c",
    "cc",
    "cpp",
    "cxx",
    "m",
    "mm",
    "s",
    "asm",
    "swift",
    "kt",
    "kts",
    "java",
    "gradle",
    "pom",
    "podspec",
    "plist",
    "pbxproj",
    "xcconfig",
    "xcscheme",
    "xcprivacy",
    "strings",
    "modulemap",
    "storyboard",
    "xib",
    "pch",
    "entitlements",
    "gyp",
    "gypi",
    "cmake",
    "mk",
    "rb",
    "py",
    "pl",
    "go",
    "rs",
    "cs",
];

/// Whether only a file's first line says whether a JavaScript runtime runs
/// it: it has no extension, an empty one, or one that is neither source nor
/// one of [`NON_SCRIPT_EXTENSIONS`]. A `bin` target such as `bin/cli` or
/// `bin/cli.sh` is run by its shebang line, and Node runs a file of any
/// other extension as CommonJS.
fn may_be_shebang_script(relative_path: &Path) -> bool {
    if relative_path.file_name().is_none() {
        return false;
    }
    let Some(extension) = relative_path.extension() else {
        return true;
    };
    let extension = extension.as_encoded_bytes();
    let listed = |extensions: &[&str]| {
        extensions
            .iter()
            .any(|listed| listed.as_bytes().eq_ignore_ascii_case(extension))
    };
    extension.is_empty() || !(listed(SOURCE_EXTENSIONS) || listed(NON_SCRIPT_EXTENSIONS))
}

/// Opens a package file to read its first line, without following a symlink
/// or waiting on a FIFO: only a regular file comes back.
fn open_regular_file(path: &Path) -> Option<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

/// The extension to parse a script as, when `head`, its first bytes,
/// opens with a shebang line that runs a JavaScript runtime directly or
/// through `env` (`#!/usr/bin/env node`, `#!/usr/bin/node`,
/// `#!/usr/bin/env -S node --flag`): `js` for Node.js and Bun, `ts` for Deno,
/// tsx and ts-node, which run TypeScript.
pub fn shebang_script_extension(head: &[u8]) -> Option<&'static str> {
    let head = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    let line = head.strip_prefix(b"#!")?;
    let line = line.split(|&byte| byte == b'\n').next().unwrap_or(line);
    let line = String::from_utf8_lossy(line);
    let mut words = line.split_ascii_whitespace();
    let mut program = shebang_program_name(words.next()?);
    // Past env's options, the ones that take a value too, and the variables
    // it sets; then past a package runner's options.
    if program == "env" {
        program = next_shebang_program(&mut words, &["-u", "--unset", "-C", "--chdir"])?;
    }
    if matches!(program.as_str(), "npx" | "pnpx" | "bunx") {
        program = next_shebang_program(&mut words, &["-p", "--package"])?;
    }
    match program.as_str() {
        "node" | "nodejs" | "bun" | "zx" => Some("js"),
        "deno" | "tsx" | "ts-node" => Some("ts"),
        _ => None,
    }
}

/// A shebang program's name: the last part of its path, in lower case,
/// without `.exe` or a version (`node20`, `node-18`).
fn shebang_program_name(word: &str) -> String {
    let name = word
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(word)
        .to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    name.trim_end_matches(|character: char| {
        character.is_ascii_digit() || matches!(character, '.' | '-' | '_')
    })
    .to_owned()
}

/// The program `words` go on to run, past options (skipping the value of
/// one of `valued`) and variable assignments.
fn next_shebang_program<'w>(
    words: &mut impl Iterator<Item = &'w str>,
    valued: &[&str],
) -> Option<String> {
    while let Some(word) = words.next() {
        if word.starts_with('-') {
            if valued.contains(&word) {
                words.next();
            }
        } else if !word.contains('=') {
            return Some(shebang_program_name(word));
        }
    }
    None
}

/// [`shebang_script_extension`] for a file read from `reader`, by its first
/// [`SHEBANG_BYTES`].
fn reads_as_shebang_script(reader: impl std::io::Read) -> bool {
    lpm_common::read_stream_prefix(reader, SHEBANG_BYTES as u64)
        .is_ok_and(|head| shebang_script_extension(&head).is_some())
}

/// Paths a tag's [`TagFiles`] lists; `file_count` counts the rest.
const MAX_TAG_FILES: usize = 5;

/// Most bytes of package file names code the package runs may name before
/// any test file counts as one it could run.
const MAX_RUNTIME_REFERENCE_BYTES: usize = 4 * 1024 * 1024;

/// Most bytes of package file names a package's test files name together.
/// Past them, a reached test file counts as one whose references aren't
/// known, whatever order the files were read in.
const MAX_TEST_REFERENCE_BYTES: usize = 4 * 1024 * 1024;

/// Test files a budget left unread whose paths reachability remembers.
const MAX_UNREAD_TEST_PATHS: usize = 4096;

/// Source files a budget or file limit left unread, as far as test-file
/// reachability needs them: code the package runs that could name any test
/// file, and test files a reference could reach without the analysis
/// following what they name. Input fingerprints hash it too, since it
/// changes what reachability concludes.
#[derive(Debug, Default)]
struct UnreadFiles {
    runtime: bool,
    tests: Vec<String>,
    unknown_tests: bool,
}

impl UnreadFiles {
    fn note_test(&mut self, path: &str) {
        if self.tests.len() < MAX_UNREAD_TEST_PATHS {
            self.tests.push(path.to_owned());
        } else {
            self.unknown_tests = true;
        }
    }

    fn hash_into(&self, hasher: &mut Sha256) {
        hasher.update(b"unread\0");
        hasher.update([u8::from(self.runtime), u8::from(self.unknown_tests)]);
        for path in &self.tests {
            hasher.update(path.as_bytes());
            hasher.update(b"\0");
        }
    }
}

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
    /// The size the path walk saw. Walks over an open package directory
    /// don't stat entries and leave it 0: their reads take the size from
    /// the opened file instead.
    size: u64,
}

/// The source files a directory walk found: for the package's code and for
/// its tests, the first in read order up to the budget's file limit, and how
/// many files there were in all.
struct SourceFiles {
    runtime: FirstFiles,
    tests: FirstFiles,
    found: usize,
    runtime_found: usize,
}

impl SourceFiles {
    fn new(limits: ScanLimits) -> Self {
        Self {
            runtime: FirstFiles::new(limits.files),
            tests: FirstFiles::new(limits.test_files),
            found: 0,
            runtime_found: 0,
        }
    }

    /// Adds a file the walk found, and says whether a file limit left a file
    /// out.
    fn insert(&mut self, file: SourceFile) -> bool {
        self.found += 1;
        if file.role.is_test() {
            self.tests.insert(file)
        } else {
            self.runtime_found += 1;
            self.runtime.insert(file)
        }
    }

    /// The files kept, in read order, and how many the walk found.
    fn into_read_order(self) -> (Vec<SourceFile>, usize) {
        let mut files = self.runtime.into_sorted_vec();
        files.extend(self.tests.into_sorted_vec());
        (files, self.found)
    }

    /// Whether a file limit left out a file of the code the package runs.
    fn left_out_runtime(&self) -> bool {
        self.runtime_found > self.runtime.len()
    }

    /// Whether a file limit left out a test file.
    fn left_out_tests(&self) -> bool {
        self.found - self.runtime_found > self.tests.len()
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

    fn len(&self) -> usize {
        match &self.files {
            FirstFilesState::Collecting(files) => files.len(),
            FirstFilesState::Limited(files) => files.len(),
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
    /// The test files the analysis read that count as code the package runs,
    /// because its manifest names them or its code reaches them, sorted, as
    /// package-relative paths spelled as the package spells them, so a
    /// caller can open them: a caller that reads only package code can read
    /// these too. Only a fresh analysis fills it: it isn't stored, so a
    /// cached analysis has none.
    #[serde(skip)]
    pub runtime_test_files: Vec<PathBuf>,
    /// Of `unparsed_files`, those of code the package runs, test files that
    /// count as package code included. Like `runtime_test_files`, only a
    /// fresh analysis fills it.
    #[serde(skip)]
    pub runtime_unparsed_files: usize,
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
    let mut manifests = Vec::new();
    collect_source_files_recursive(
        package_dir,
        Path::new(""),
        &mut sources,
        &mut native_artifacts,
        &mut manifests,
    );
    let mut unread = UnreadFiles {
        runtime: sources.left_out_runtime(),
        unknown_tests: sources.left_out_tests(),
        ..UnreadFiles::default()
    };
    let (candidates, found) = sources.into_read_order();
    let mut budget = ScanBudget::new(limits);
    let admitted: Vec<SourceFile> = candidates
        .into_iter()
        .filter(|file| {
            let admitted = budget.admit(file.role.is_test(), limits.read_bytes(file.size));
            if !admitted {
                if file.role.is_test() {
                    unread.note_test(&path_to_slash(&file.path));
                } else {
                    unread.runtime = true;
                }
            }
            admitted
        })
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
    analyzer.unread = unread;
    for (file, result) in admitted.iter().zip(results) {
        match result {
            Some(result) => analyzer.merge(result),
            None if file.role.is_test() => analyzer.unread.note_test(&path_to_slash(&file.path)),
            None => analyzer.unread.runtime = true,
        }
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
    manifests.sort_unstable();
    analyzer.nested_manifests_left_out |= manifests.len() > MAX_NESTED_MANIFESTS;
    for relative in manifests.iter().take(MAX_NESTED_MANIFESTS) {
        match lpm_common::read_file_capped(
            &package_dir.join(relative),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(bytes) => analyzer.note_nested_manifest(relative, &bytes),
            Err(_) => analyzer.note_nested_manifest_left_out(),
        }
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
    let (analysis, fingerprint, directory_changed) =
        analyze_package_from_open_dir_reading(package_dir, contents, true);
    if !directory_changed {
        return (analysis, fingerprint);
    }
    // Files read through a held handle came from a directory that has since
    // been replaced; read the package again by path, as it is now.
    let (analysis, fingerprint, _) =
        analyze_package_from_open_dir_reading(package_dir, contents, false);
    (analysis, fingerprint)
}

fn analyze_package_from_open_dir_reading(
    package_dir: &cap_std::fs::Dir,
    contents: PackageDirectory<'_>,
    hold_directories: bool,
) -> (PackageAnalysis, Option<String>, bool) {
    let limits = ScanLimits::INSTALL;
    let mut sources = SourceFiles::new(limits);
    let mut native_artifacts = Vec::new();
    let mut manifests = Vec::new();
    let mut discovery_limit_reached = false;
    let rules = WalkRules::new(package_dir, contents);
    let discovery_complete = collect_cap_fingerprint_files(
        package_dir,
        Path::new(""),
        &rules,
        &mut sources,
        &mut native_artifacts,
        &mut manifests,
        &mut discovery_limit_reached,
    )
    .is_ok();
    native_artifacts.sort_unstable();
    let left_out = UnreadFiles {
        runtime: sources.left_out_runtime(),
        unknown_tests: sources.left_out_tests(),
        ..UnreadFiles::default()
    };
    let (candidates, found) = sources.into_read_order();
    let candidate_count = candidates.len();
    let (mut analyzer, mut fingerprint, over_budget, directory_changed) =
        analyze_cap_files_with_fingerprint(
            package_dir,
            candidates,
            limits,
            discovery_complete,
            hold_directories,
            left_out,
        );
    let skipped = found - candidate_count + over_budget;
    analyzer.skip(skipped);
    if !discovery_complete {
        analyzer.unread.runtime = true;
    }
    let limit_reached = discovery_limit_reached || skipped > 0;
    analyzer.limit_reached |= limit_reached;
    if let Some(hasher) = fingerprint.as_mut() {
        hash_native_artifacts(hasher, &native_artifacts);
    }
    for artifact in &native_artifacts {
        analyzer.note_entry(artifact);
    }
    match read_nested_manifests_from_open_dir(package_dir, &mut manifests, fingerprint.as_mut()) {
        Ok(read) => {
            analyzer.nested_manifests_left_out |= manifests.len() > MAX_NESTED_MANIFESTS;
            for (relative, bytes) in &read {
                match bytes {
                    Some(bytes) => analyzer.note_nested_manifest(relative, bytes),
                    None => analyzer.note_nested_manifest_left_out(),
                }
            }
        }
        Err(_) => {
            fingerprint = None;
            analyzer.nested_manifests_left_out = true;
        }
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
    let unread_for_fingerprint = UnreadFiles {
        runtime: analyzer.unread.runtime,
        tests: analyzer.unread.tests.clone(),
        unknown_tests: analyzer.unread.unknown_tests,
    };
    let mut analysis = analyzer.finish(manifest.as_deref());
    if analysis.meta.input_incomplete {
        fingerprint = None;
    }
    analysis.meta.input_incomplete = fingerprint.is_none();
    let fingerprint = fingerprint.map(|mut hasher| {
        hasher.update(b"limits\0");
        hasher.update([u8::from(limit_reached)]);
        unread_for_fingerprint.hash_into(&mut hasher);
        format!("sha256-{}", hex::encode(hasher.finalize()))
    });
    (analysis, fingerprint, directory_changed)
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
    let mut manifests = Vec::new();
    let mut discovery_limit_reached = false;
    let rules = WalkRules::new(package_dir, contents);
    collect_cap_fingerprint_files(
        package_dir,
        Path::new(""),
        &rules,
        &mut sources,
        &mut native_artifacts,
        &mut manifests,
        &mut discovery_limit_reached,
    )?;
    native_artifacts.sort_unstable();
    let mut unread = UnreadFiles {
        runtime: sources.left_out_runtime(),
        unknown_tests: sources.left_out_tests(),
        ..UnreadFiles::default()
    };
    let (candidates, found) = sources.into_read_order();

    let mut hasher = new_fingerprint_hasher();
    let mut budget = ScanBudget::new(limits);
    let mut over_budget = 0usize;
    let mut directories = PackageDirs::new(package_dir);
    for source_file in &candidates {
        let (file, size) = directories.open_file(&source_file.path)?;
        if !budget.admit(source_file.role.is_test(), limits.read_bytes(size)) {
            over_budget += 1;
            if source_file.role.is_test() {
                unread.note_test(&path_to_slash(&source_file.path));
            } else {
                unread.runtime = true;
            }
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
    directories.verify_unchanged()?;
    hash_native_artifacts(&mut hasher, &native_artifacts);
    read_nested_manifests_from_open_dir(package_dir, &mut manifests, Some(&mut hasher))?;

    match digest_package_manifest_from_open_dir(package_dir)? {
        Some((size, bytes_read, digest)) => {
            hash_fingerprint_record_digest(&mut hasher, b"package.json", size, bytes_read, digest)
        }
        None => hasher.update(b"package.json\0missing\0"),
    }

    let skipped = found - candidates.len() + over_budget;
    hasher.update(b"limits\0");
    hasher.update([u8::from(discovery_limit_reached || skipped > 0)]);
    unread.hash_into(&mut hasher);

    Ok(format!("sha256-{}", hex::encode(hasher.finalize())))
}

/// Whether the regular file `name` in `directory` is a script a JavaScript
/// runtime runs, by its shebang line, opened as the walk's reads open a file.
fn opens_as_shebang_script(directory: &cap_std::fs::Dir, name: &std::ffi::OsStr) -> bool {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    directory
        .open_with(name, &options)
        .is_ok_and(reads_as_shebang_script)
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
    manifests: &mut Vec<std::path::PathBuf>,
    limit_reached: &mut bool,
) -> std::io::Result<()> {
    use cap_fs_ext::DirExt as _;

    for entry in directory.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        // The directory entry's type spares a stat per entry; a file system
        // that does not report it falls back to one. Every later open refuses
        // symlinks, so an entry replaced after the read cannot redirect it.
        let mut file_type = entry.file_type()?;
        if !(file_type.is_dir() || file_type.is_file() || file_type.is_symlink()) {
            file_type = directory.symlink_metadata(&name)?.file_type();
        }
        if file_type.is_symlink() {
            continue;
        }
        let relative = relative_dir.join(&name);
        if !rules.reads(&relative, file_type.is_dir()) {
            continue;
        }
        if file_type.is_dir() {
            let child = directory.open_dir_nofollow(&name)?;
            collect_cap_fingerprint_files(
                &child,
                &relative,
                rules,
                files,
                native_artifacts,
                manifests,
                limit_reached,
            )?;
        } else if file_type.is_file() {
            if PackageAnalyzer::should_scan(&relative, 0)
                || (may_be_shebang_script(&relative) && opens_as_shebang_script(directory, &name))
            {
                let candidate = SourceFile {
                    role: FileRole::of(&relative),
                    path: relative,
                    size: 0,
                };
                *limit_reached |= files.insert(candidate);
            } else if PackageAnalyzer::is_native_artifact(&relative) {
                if native_artifacts.len() < MAX_FILES_PER_PACKAGE {
                    native_artifacts.push(relative);
                } else {
                    *limit_reached = true;
                }
            } else if is_nested_manifest(&relative) {
                manifests.push(relative);
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

/// The directories of one package that recent opens went through, so that
/// opening the next file of the same directory costs one `openat` rather than
/// one per path component. Every handle was opened from the package root, or
/// from another such handle, without following links.
///
/// A held handle keeps reading a directory that was replaced after it was
/// opened, where reopening the path for each file would see the new one, so
/// [`Self::verify_unchanged`] checks every directory still has the identity
/// it had when it was opened.
struct PackageDirs<'a> {
    root: &'a cap_std::fs::Dir,
    /// The last directory opened and its ancestors below the root,
    /// shallowest first. Files are read in path order, so the next file's
    /// directory usually shares most of this chain.
    chain: Vec<(std::path::PathBuf, cap_std::fs::Dir)>,
    opened: std::collections::BTreeMap<std::path::PathBuf, DirectoryIdentity>,
    reopened_changed: bool,
    tracking_limit: usize,
    holds_directories: bool,
}

/// Set once any analysis thread runs out of descriptors. From then on no
/// [`PackageDirs`] holds directory handles, so the threads still holding
/// theirs give them back at their next open rather than starving the rest.
static DIRECTORY_HANDLES_EXHAUSTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn of(directory: &cap_std::fs::Dir) -> std::io::Result<Self> {
        use cap_fs_ext::MetadataExt as _;

        let metadata = directory.dir_metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_FIRST_SOURCE_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

fn package_directory_changed() -> std::io::Error {
    std::io::Error::other("a package directory changed while its files were read")
}

impl<'a> PackageDirs<'a> {
    /// Each held handle is a descriptor on top of the files every analysis
    /// thread has open, so a deep path keeps only its deepest directories.
    const MAX_HELD: usize = 8;
    /// Directories whose identities a package's read keeps for the final
    /// check. Past this, files are reached holding no handle, so nothing they
    /// read can come from a replaced directory and nothing more is tracked.
    const MAX_TRACKED: usize = 4096;

    fn new(root: &'a cap_std::fs::Dir) -> Self {
        Self::with_tracking_limit(root, Self::MAX_TRACKED)
    }

    fn with_tracking_limit(root: &'a cap_std::fs::Dir, tracking_limit: usize) -> Self {
        Self {
            root,
            chain: Vec::with_capacity(Self::MAX_HELD),
            opened: std::collections::BTreeMap::new(),
            reopened_changed: false,
            tracking_limit,
            holds_directories: true,
        }
    }

    /// Reaches every file by its path, holding one directory at a time.
    fn holding_none(root: &'a cap_std::fs::Dir) -> Self {
        Self {
            holds_directories: false,
            ..Self::with_tracking_limit(root, 0)
        }
    }

    /// Whether every directory opened below the root still has the identity
    /// it had then, reopened top-down from the root without following links.
    /// Gives back the handles the reads held first.
    fn verify_unchanged(&mut self) -> std::io::Result<()> {
        self.chain.clear();
        if self.reopened_changed {
            return Err(package_directory_changed());
        }
        match self.verify_holding_ancestors() {
            Err(error) if runs_out_of_descriptors(&error) => self.verify_holding_one_directory(),
            verified => verified,
        }
    }

    fn verify_holding_ancestors(&self) -> std::io::Result<()> {
        use cap_fs_ext::DirExt as _;

        let mut ancestors: Vec<(&Path, cap_std::fs::Dir)> = Vec::new();
        // Path order visits each directory after its ancestors.
        for (path, identity) in &self.opened {
            let parent = path.parent().unwrap_or_else(|| Path::new(""));
            while ancestors
                .last()
                .is_some_and(|(ancestor, _)| *ancestor != parent)
            {
                ancestors.pop();
            }
            let name = path.file_name().ok_or_else(package_directory_changed)?;
            let current = match ancestors.last() {
                Some((_, directory)) => directory.open_dir_nofollow(name)?,
                None if parent.as_os_str().is_empty() => self.root.open_dir_nofollow(name)?,
                None => return Err(package_directory_changed()),
            };
            if DirectoryIdentity::of(&current)? != *identity {
                return Err(package_directory_changed());
            }
            ancestors.push((path, current));
        }
        Ok(())
    }

    fn verify_holding_one_directory(&self) -> std::io::Result<()> {
        use cap_fs_ext::DirExt as _;

        for (path, identity) in &self.opened {
            let mut current: Option<cap_std::fs::Dir> = None;
            for name in path.components() {
                current = Some(match &current {
                    Some(directory) => directory.open_dir_nofollow(name)?,
                    None => self.root.open_dir_nofollow(name)?,
                });
            }
            let current = current.ok_or_else(package_directory_changed)?;
            if DirectoryIdentity::of(&current)? != *identity {
                return Err(package_directory_changed());
            }
        }
        Ok(())
    }

    fn record_opened(&mut self, path: &Path, directory: &cap_std::fs::Dir) -> std::io::Result<()> {
        let identity = DirectoryIdentity::of(directory)?;
        match self.opened.entry(path.to_path_buf()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(identity);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                self.reopened_changed |= *entry.get() != identity;
            }
        }
        Ok(())
    }

    fn open_file(&mut self, relative_path: &Path) -> std::io::Result<(cap_std::fs::File, u64)> {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

        let mut components = relative_path.components();
        let leaf = match components.next_back() {
            Some(std::path::Component::Normal(name)) => name,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "source path has no file name",
                ));
            }
        };
        let parent_path = components.as_path();
        if parent_path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "source path contains an unsafe component",
            ));
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let hold = self.holds_directories
            && self.opened.len() < self.tracking_limit
            && !DIRECTORY_HANDLES_EXHAUSTED.load(std::sync::atomic::Ordering::Relaxed);
        let file = if hold {
            self.open_through_chain(parent_path, leaf, &options)?
        } else {
            self.chain.clear();
            self.open_holding_one_directory(parent_path, leaf, &options, false)?
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.is_symlink() {
            return Err(std::io::Error::other(
                "source path is not a safe regular file",
            ));
        }
        #[cfg(test)]
        if let Some(hook) = AFTER_FIRST_SOURCE_OPEN.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
        Ok((file, metadata.len()))
    }

    fn open_through_chain(
        &mut self,
        parent_path: &Path,
        leaf: &std::ffi::OsStr,
        options: &cap_std::fs::OpenOptions,
    ) -> std::io::Result<cap_std::fs::File> {
        match self
            .directory(parent_path)
            .and_then(|parent| parent.open_with(leaf, options))
        {
            // Give the held handles back and open this file holding one
            // directory at a time, as reopening the path for each file did.
            Err(error) if runs_out_of_descriptors(&error) => {
                DIRECTORY_HANDLES_EXHAUSTED.store(true, std::sync::atomic::Ordering::Relaxed);
                self.chain.clear();
                self.open_holding_one_directory(parent_path, leaf, options, false)
            }
            opened => opened,
        }
    }

    /// The handle of `relative`, a path of normal components, opened from
    /// its deepest held ancestor.
    fn directory(&mut self, relative: &Path) -> std::io::Result<&cap_std::fs::Dir> {
        use cap_fs_ext::DirExt as _;

        if relative.as_os_str().is_empty() {
            return Ok(self.root);
        }
        while self
            .chain
            .last()
            .is_some_and(|(held, _)| !relative.starts_with(held))
        {
            self.chain.pop();
        }
        let held_depth = self
            .chain
            .last()
            .map_or(0, |(held, _)| held.components().count());
        let mut prefix: std::path::PathBuf = relative.components().take(held_depth).collect();
        for name in relative.components().skip(held_depth) {
            let next = match self.chain.last() {
                Some((_, directory)) => directory.open_dir_nofollow(name)?,
                None => self.root.open_dir_nofollow(name)?,
            };
            prefix.push(name);
            self.record_opened(&prefix, &next)?;
            if self.chain.len() == Self::MAX_HELD {
                self.chain.remove(0);
            }
            self.chain.push((prefix.clone(), next));
        }
        Ok(&self
            .chain
            .last()
            .expect("a non-empty path below its deepest held ancestor")
            .1)
    }

    fn open_holding_one_directory(
        &mut self,
        parent_path: &Path,
        leaf: &std::ffi::OsStr,
        options: &cap_std::fs::OpenOptions,
        track: bool,
    ) -> std::io::Result<cap_std::fs::File> {
        use cap_fs_ext::DirExt as _;

        let mut prefix = std::path::PathBuf::new();
        let mut current: Option<cap_std::fs::Dir> = None;
        for name in parent_path.components() {
            let next = match &current {
                Some(directory) => directory.open_dir_nofollow(name)?,
                None => self.root.open_dir_nofollow(name)?,
            };
            if track {
                prefix.push(name);
                self.record_opened(&prefix, &next)?;
            }
            current = Some(next);
        }
        current
            .as_ref()
            .map_or(self.root, |directory| directory)
            .open_with(leaf, options)
    }
}

#[cfg(unix)]
fn runs_out_of_descriptors(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

#[cfg(not(unix))]
fn runs_out_of_descriptors(_error: &std::io::Error) -> bool {
    false
}

fn open_cap_source_file(
    root: &cap_std::fs::Dir,
    relative_path: &Path,
) -> std::io::Result<(cap_std::fs::File, u64)> {
    PackageDirs::new(root).open_file(relative_path)
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
    analysis: FileAnalysisResult,
}

/// Reads and analyzes one opened source file; on a failed read, the path of
/// the file it couldn't read.
fn analyze_open_cap_source_file(
    source_file: OpenCapSourceFile,
    limits: ScanLimits,
    comment_buf: &mut Vec<u8>,
) -> Result<ScannedCapSourceFile, PathBuf> {
    let mut file = source_file.file.into_std();
    let sampled = source_file.size > limits.full_file_bytes;
    let bytes = if sampled {
        read_oversized_source_sample_from_open_file(
            &mut file,
            source_file.size,
            limits.sample_bytes,
        )
        .ok()
    } else {
        lpm_common::read_file_capped_from_open_file(file, &source_file.path, limits.full_file_bytes)
            .ok()
            .map(|(bytes, _)| bytes)
    };
    let Some(bytes) = bytes else {
        return Err(source_file.path);
    };
    // A name that isn't UTF-8 is read lossily, as the path walk reads it.
    let analysis = if sampled {
        analyze_oversized_source_sample(&source_file.path, source_file.size, &bytes, comment_buf)
    } else {
        analyze_package_file(&source_file.path, &bytes, comment_buf)
    };
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
/// Analyses `files` and fingerprints what it read. The last value says a
/// directory a held handle read from was replaced meanwhile, which also
/// drops the fingerprint.
fn analyze_cap_files_with_fingerprint(
    package_dir: &cap_std::fs::Dir,
    files: Vec<SourceFile>,
    limits: ScanLimits,
    fingerprint_valid: bool,
    hold_directories: bool,
    left_out: UnreadFiles,
) -> (PackageAnalyzer, Option<Sha256>, usize, bool) {
    use rayon::prelude::*;

    let mut analyzer = PackageAnalyzer::with_limits(limits);
    analyzer.unread = left_out;
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

    let mut directories = if hold_directories {
        PackageDirs::new(package_dir)
    } else {
        PackageDirs::holding_none(package_dir)
    };
    let mut files = files.into_iter().peekable();
    while files.peek().is_some() {
        let mut opened = Vec::with_capacity(batch_size);
        for source_file in files.by_ref().take(batch_size) {
            let (file, size) = match directories.open_file(&source_file.path) {
                Ok(opened) => opened,
                Err(_) => {
                    fingerprint = None;
                    analyzer.note_unread(source_file.role.is_test(), &source_file.path);
                    continue;
                }
            };
            if !budget.admit(source_file.role.is_test(), limits.read_bytes(size)) {
                over_budget += 1;
                analyzer.note_unread(source_file.role.is_test(), &source_file.path);
                continue;
            }
            opened.push(OpenCapSourceFile {
                path: source_file.path,
                file,
                size,
            });
        }

        let results: Vec<Result<ScannedCapSourceFile, PathBuf>> = if opened.len() >= 20 {
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
                Err(path) => {
                    fingerprint = None;
                    analyzer.note_unread(FileRole::of(&path).is_test(), &path);
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
            analyzer.merge(scanned.analysis);
        }
    }
    let directory_changed = directories.verify_unchanged().is_err();
    if directory_changed {
        fingerprint = None;
    }
    (analyzer, fingerprint, over_budget, directory_changed)
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

/// The `package.json` files below the root a walk found, read from the open
/// package directory in path order and hashed into `hasher` as inputs of the
/// analysis. Past [`MAX_NESTED_MANIFESTS`] the rest are left unread, which the
/// analysis counts as left out and the hash records.
/// The first [`MAX_NESTED_MANIFESTS`] `package.json` files below the root,
/// in order, each with its content, or `None` when it's past the
/// configuration file cap.
fn read_nested_manifests_from_open_dir(
    package_dir: &cap_std::fs::Dir,
    manifests: &mut [PathBuf],
    mut hasher: Option<&mut Sha256>,
) -> std::io::Result<Vec<(PathBuf, Option<Vec<u8>>)>> {
    manifests.sort_unstable();
    let mut read = Vec::with_capacity(manifests.len().min(MAX_NESTED_MANIFESTS));
    for relative in manifests.iter().take(MAX_NESTED_MANIFESTS) {
        let (file, size) = open_cap_source_file(package_dir, relative)?;
        if size > lpm_common::CONFIG_FILE_SIZE_CAP_BYTES {
            if let Some(hasher) = hasher.as_deref_mut() {
                hasher.update(b"manifest\0left out\0");
                hasher.update(relative.as_os_str().as_encoded_bytes());
                hasher.update(b"\0");
                hasher.update(size.to_le_bytes());
            }
            read.push((relative.clone(), None));
            continue;
        }
        let content = lpm_common::read_file_capped_from_open_file(
            file.into_std(),
            relative,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .map_err(std::io::Error::other)?
        .0;
        if let Some(hasher) = hasher.as_deref_mut() {
            hash_fingerprint_record_digest(
                hasher,
                relative.as_os_str().as_encoded_bytes(),
                size,
                content.len() as u64,
                Sha256::digest(&content).into(),
            );
        }
        read.push((relative.clone(), Some(content)));
    }
    if manifests.len() > MAX_NESTED_MANIFESTS
        && let Some(hasher) = hasher
    {
        hasher.update(b"manifests\0left out\0");
    }
    Ok(read)
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
    /// The package files the file's string literals name, which decide
    /// whether a test file is code the package runs.
    pub(crate) references: roles::FileReferences,
    /// The file starts a script or a worker from a path it computes.
    pub(crate) loads_computed_code: bool,
    /// [`exact_path`] of the file's path, when `path` spells it differently.
    pub(crate) exact_path: Option<Box<Path>>,
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
    Some(analyze_package_file(&file.path, &raw_content, comment_buf))
}

/// Core scan pass without the filesystem read — takes the file's
/// package-relative path and raw bytes and returns the same
/// `FileAnalysisResult` that [`analyze_package`] computes for that file. The
/// fused-scan path in `lpm-store` invokes this during tar extraction, using
/// bytes the extractor already had in hand instead of re-reading the file a
/// second time.
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
    let references = match &context.path_literals {
        Some(paths) => roles::FileReferences::resolve(
            filename,
            paths.literals.iter().map(String::as_str),
            paths.complete,
        ),
        None => {
            let in_test_file = roles::is_test_path(filename);
            let literals: Vec<std::borrow::Cow<'_, str>> = supply_chain::quoted_literals(stripped)
                .map(roles::decode_string_escapes)
                .filter(|literal| roles::may_name_package_file(literal, in_test_file))
                .collect();
            roles::FileReferences::resolve(filename, literals.iter().map(AsRef::as_ref), true)
        }
    };
    let loads_computed_code = match &context.calls {
        Some(calls) => calls.computed_script.is_some(),
        None => computed_script_patterns()
            .iter()
            .any(|pattern| context.find_with_context(pattern, false).is_some()),
    };

    FileAnalysisResult {
        path: filename.to_owned(),
        exact_path: None,
        eval_calls,
        references,
        loads_computed_code,
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

/// What starting a script or a worker from a computed path looks like in
/// source the parser couldn't read.
fn computed_script_patterns() -> &'static [regex::Regex] {
    static INSTANCE: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();
    INSTANCE.get_or_init(|| {
        [
            r#"\bfork\s*\(\s*[^"'`\s)]"#,
            r#"\bnew\s+Worker\s*\(\s*[^"'`\s)]"#,
        ]
        .into_iter()
        .map(|pattern| regex::Regex::new(pattern).expect("computed script pattern must compile"))
        .collect()
    })
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
    // A literal between the two samples could name any file.
    result.references = roles::FileReferences::unknown();
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
    result.exact_path = exact_path(relative_path);
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
        exact_path: exact_path(relative_path),
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

/// The path itself, when [`path_to_slash`] changed more than its separators:
/// a name that isn't UTF-8, or one holding `\\` where that isn't a
/// separator. Opening the file again takes this spelling.
fn exact_path(relative: &Path) -> Option<Box<Path>> {
    let changed = match relative.to_str() {
        None => true,
        Some(text) => !cfg!(windows) && text.contains('\\'),
    };
    changed.then(|| relative.into())
}

/// [`analyze_bytes_with_scratch`] for the package file at `relative`.
fn analyze_package_file(
    relative: &Path,
    raw_content: &[u8],
    comment_buf: &mut Vec<u8>,
) -> FileAnalysisResult {
    let mut result =
        analyze_bytes_with_scratch(&path_to_slash(relative), raw_content, comment_buf, true);
    result.exact_path = exact_path(relative);
    result
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
    manifests: &mut Vec<std::path::PathBuf>,
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
            collect_source_files_recursive(
                package_dir,
                &relative,
                files,
                native_artifacts,
                manifests,
            );
        } else if !metadata.is_file() {
            continue;
        } else if PackageAnalyzer::reads_as_source(&relative, &entry.path()) {
            files.insert(SourceFile {
                role: FileRole::of(&relative),
                path: relative,
                size: metadata.len(),
            });
        } else if PackageAnalyzer::is_native_artifact(&relative) {
            native_artifacts.push(relative);
        } else if is_nested_manifest(&relative) {
            manifests.push(relative);
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
    let mut peer_dependencies = parse_deps_map(parsed.get("peerDependencies"));
    if let (Some(peers), Some(meta)) = (
        peer_dependencies.as_mut(),
        parsed
            .get("peerDependenciesMeta")
            .and_then(|meta| meta.as_object()),
    ) {
        peers.retain(|name, _| {
            !meta
                .get(name)
                .and_then(|entry| entry.get("optional"))
                .is_some_and(is_truthy)
        });
    }

    Some((
        manifest::analyze_manifest_with_privacy(
            license,
            private_package,
            dependencies.as_ref(),
            optional_dependencies.as_ref(),
            peer_dependencies.as_ref(),
        ),
        references,
    ))
}

/// Whether JavaScript reads `value` as true, as npm reads `peerDependenciesMeta`.
fn is_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => true,
    }
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
/// A test file's tags wait for the manifest and the rest of the package: they
/// count as the package's own when its lifecycle scripts or entry points name
/// the file or code it runs reaches it ([`roles::reachable_tests`]), and are
/// reported as tests-only otherwise.
#[derive(Debug)]
pub struct PackageAnalyzer {
    budget: ScanBudget,
    runtime: TagTotals,
    tests: Vec<FileAnalysisResult>,
    /// The package files code the package runs names, for
    /// [`roles::reachable_tests`].
    runtime_references: Vec<String>,
    runtime_reference_bytes: usize,
    /// Code the package runs loads code from a path it computes, or some of
    /// it wasn't read whole, so any test file could be code it runs.
    runtime_is_opaque: bool,
    /// Source files a budget or file limit left unread.
    unread: UnreadFiles,
    test_reference_bytes: usize,
    native_artifacts: Vec<String>,
    oversized_source_files: Vec<OversizedSourceFileEvidence>,
    files_scanned: usize,
    unparsed_files: usize,
    /// Of `unparsed_files`, those of files that aren't tests.
    runtime_unparsed_files: usize,
    /// The package's `package.json` files below its root, and whether more
    /// were found than are kept.
    nested_manifests: Vec<roles::NestedManifest>,
    /// `package.json` files below the root handed over, read or not.
    nested_manifests_seen: usize,
    nested_manifests_left_out: bool,
    nested_manifest_budget: roles::NestedManifestBudget,
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
            runtime_references: Vec::new(),
            runtime_reference_bytes: 0,
            runtime_is_opaque: false,
            unread: UnreadFiles::default(),
            test_reference_bytes: 0,
            native_artifacts: Vec::new(),
            oversized_source_files: Vec::new(),
            files_scanned: 0,
            unparsed_files: 0,
            runtime_unparsed_files: 0,
            nested_manifests: Vec::new(),
            nested_manifests_seen: 0,
            nested_manifests_left_out: false,
            nested_manifest_budget: roles::NestedManifestBudget::default(),
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

    /// Whether the analysis reads the file at `full_path`, whose path in the
    /// package is `relative_path`, as source: by its extension, as
    /// [`Self::should_scan`] decides, or, for a file whose extension doesn't
    /// say, by a shebang line that runs a JavaScript runtime, read from the
    /// file. That read follows no symlink and doesn't wait on a FIFO: anything
    /// but a regular file isn't source. A caller with its own source walk can
    /// read the same files with it.
    pub fn reads_as_source(relative_path: &Path, full_path: &Path) -> bool {
        Self::should_scan(relative_path, 0)
            || (may_be_shebang_script(relative_path)
                && open_regular_file(full_path).is_some_and(reads_as_shebang_script))
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
        let test = roles::is_test_path(&path);
        if !self.budget.admit(test, bytes.len() as u64) {
            self.skip(1);
            self.note_unread(test, relative_path);
            return;
        }

        let scan_start = std::time::Instant::now();
        let result = analyze_package_file(relative_path, bytes, &mut Vec::new());
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

    /// Notes a `package.json` below the package root: requiring its directory
    /// loads what it names, which can be a test file. The root manifest goes
    /// to [`Self::finish`] instead, and a manifest that isn't JSON names
    /// nothing, as Node can't load through it.
    pub fn note_nested_manifest(&mut self, relative_path: &Path, bytes: &[u8]) {
        let path = path_to_slash(relative_path);
        let Some((directory, name)) = path.rsplit_once('/') else {
            return;
        };
        if !name.eq_ignore_ascii_case("package.json") || !self.count_nested_manifest() {
            return;
        }
        // Node reads a manifest past a byte order mark. One serde can't read,
        // nested deeper than it reads or holding a number or an escape only
        // JavaScript takes, names what isn't known.
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let manifest = (!json_nests_deeper_than(bytes, MAX_JSON_NESTING))
            .then(|| serde_json::from_slice::<serde_json::Value>(bytes).ok())
            .flatten();
        self.nested_manifests.push(match manifest {
            Some(manifest) => roles::NestedManifest::from_manifest(
                directory,
                &manifest,
                &mut self.nested_manifest_budget,
            ),
            None => roles::NestedManifest::unknown(directory),
        });
    }

    /// Notes that a `package.json` below the root couldn't be read, so what it
    /// names isn't known.
    pub(crate) fn note_nested_manifest_left_out(&mut self) {
        self.count_nested_manifest();
        self.nested_manifests_left_out = true;
    }

    /// Counts a `package.json` below the root toward [`MAX_NESTED_MANIFESTS`],
    /// whether or not it can be read, as the directory walks count them.
    /// `false` once past it.
    fn count_nested_manifest(&mut self) -> bool {
        self.nested_manifests_seen += 1;
        if self.nested_manifests_seen > MAX_NESTED_MANIFESTS {
            self.nested_manifests_left_out = true;
            return false;
        }
        true
    }

    /// Read a source file a caller extracted without buffering it, from disk:
    /// an oversized one by its sample, and a file whose extension says nothing,
    /// such as `bin/cli`, which [`Self::should_buffer_source`] never buffers,
    /// when its shebang line runs a JavaScript runtime. Any other file is left alone, so a caller can hand
    /// over every file it didn't buffer.
    pub fn feed_oversized_source_file(
        &mut self,
        relative_path: &Path,
        full_path: &Path,
        size: u64,
    ) {
        let limits = self.budget.limits;
        if is_nested_manifest(relative_path) {
            if self.nested_manifests_seen >= MAX_NESTED_MANIFESTS {
                self.note_nested_manifest_left_out();
                return;
            }
            match lpm_common::read_file_capped(full_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
                Ok(bytes) => self.note_nested_manifest(relative_path, &bytes),
                Err(_) => self.note_nested_manifest_left_out(),
            }
            return;
        }
        if may_be_shebang_script(relative_path) {
            // Whether such a file is a script only its first line says, so a
            // caller buffering by name buffers none.
            if size == 0 || !open_regular_file(full_path).is_some_and(reads_as_shebang_script) {
                return;
            }
            if size <= limits.full_file_bytes {
                if let Ok(bytes) = lpm_common::read_file_capped(full_path, limits.full_file_bytes) {
                    self.feed(relative_path, &bytes);
                }
                return;
            }
        } else if !Self::should_scan(relative_path, size) {
            return;
        }
        if size <= limits.full_file_bytes || !self.admit(relative_path, limits.read_bytes(size)) {
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
        let test = roles::is_test_path(&path_to_slash(relative_path));
        let admitted = self.budget.admit(test, bytes);
        if !admitted {
            self.skip(1);
            self.note_unread(test, relative_path);
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

    /// Notes a source file the analysis didn't read: unread code the package
    /// runs could name any test file, and an unread test file could name more.
    fn note_unread(&mut self, test: bool, relative_path: &Path) {
        if test {
            self.unread.note_test(&path_to_slash(relative_path));
        } else {
            self.unread.runtime = true;
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
            self.test_reference_bytes += result.references.byte_len();
            self.tests.push(result);
        } else {
            self.runtime_unparsed_files += result.unparsed_files;
            let references = std::mem::take(&mut result.references);
            let loads_computed_code = result.source.dynamic_require || result.loads_computed_code;
            self.note_runtime_references(references, loads_computed_code);
            self.runtime.add(result);
        }
    }

    fn note_runtime_references(
        &mut self,
        references: roles::FileReferences,
        loads_computed_code: bool,
    ) {
        if self.runtime_is_opaque {
            return;
        }
        if loads_computed_code || !references.is_complete() {
            self.runtime_is_opaque = true;
            self.runtime_references = Vec::new();
            return;
        }
        self.runtime_reference_bytes += references.byte_len();
        if self.runtime_reference_bytes > MAX_RUNTIME_REFERENCE_BYTES {
            self.runtime_is_opaque = true;
            self.runtime_references = Vec::new();
            return;
        }
        self.runtime_references.extend(references.into_paths());
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
        let candidates: Vec<roles::TestFile<'_>> = test_results
            .iter()
            .map(|result| roles::TestFile {
                path: &result.path,
                references: Some(&result.references),
                loads_computed_code: result.source.dynamic_require || result.loads_computed_code,
            })
            .chain(test_addons.iter().map(|path| roles::TestFile {
                path,
                references: None,
                loads_computed_code: false,
            }))
            .collect();
        let unread_tests: Vec<&str> = self.unread.tests.iter().map(String::as_str).collect();
        let manifest_runs_unread_test = references.names(&unread_tests).contains(&true);
        // The manifest's strings resolved as paths too: a `cd`, an `npm run`
        // chain, a normalized or differently cased spelling, a directory.
        let manifest_paths = references.paths();
        let manifest_paths_complete = manifest_paths.is_complete();
        self.runtime_references.extend(manifest_paths.into_paths());
        // A manifest below the root outside test directories is how the
        // package's code loads its directory, so what it names must be known;
        // a fixture's matters once a reference reaches it.
        let nested_manifests = std::mem::take(&mut self.nested_manifests);
        let nested_manifests_known = !self.nested_manifests_left_out
            && nested_manifests
                .iter()
                .all(|manifest| manifest.is_in_a_test_directory() || manifest.is_complete());
        let manifest_paths_complete = manifest_paths_complete && nested_manifests_known;
        let named = roles::reachable_tests(
            &candidates,
            roles::Reachability {
                named_by_manifest: references.names(&queried),
                runtime_references: &self.runtime_references,
                runtime_is_opaque: self.runtime_is_opaque
                    || self.unread.runtime
                    || references.code().runs_unread_code
                    || manifest_runs_unread_test
                    || !manifest_paths_complete,
                package_name: references.code().name.as_deref(),
                unread_tests: &self.unread.tests,
                unknown_tests_left_out: self.unread.unknown_tests,
                test_references_incomplete: self.test_reference_bytes > MAX_TEST_REFERENCE_BYTES,
                nested_manifests: &nested_manifests,
            },
        );
        drop(candidates);
        let (named_results, named_addons) = named.split_at(test_results.len());
        let named_addons: HashMap<&str, bool> = test_addons
            .iter()
            .copied()
            .zip(named_addons.iter().copied())
            .collect();
        let mut runtime_test_files = Vec::new();
        let mut runtime_unparsed_files = self.runtime_unparsed_files;
        for (result, named) in test_results.into_iter().zip(named_results.iter().copied()) {
            if named {
                runtime_unparsed_files += result.unparsed_files;
                runtime_test_files.push(
                    result
                        .exact_path
                        .as_deref()
                        .map_or_else(|| PathBuf::from(&result.path), Path::to_path_buf),
                );
                self.runtime.add(result);
            } else {
                tests.add(result);
            }
        }
        runtime_test_files.sort_unstable();
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
            analyzed_at: lpm_common::Timestamp::now().to_rfc3339(),
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
                runtime_test_files,
                runtime_unparsed_files,
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

/// Read a cached `.lpm-security.json` file from a retained directory capability.
pub fn read_cached_analysis_from_open_dir(
    package_dir: &cap_std::fs::Dir,
) -> Option<PackageAnalysis> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = package_dir.open_with(".lpm-security.json", &options).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > lpm_common::STATE_FILE_SIZE_CAP_BYTES {
        return None;
    }
    let bytes =
        lpm_common::read_stream_capped(file.into_std(), lpm_common::STATE_FILE_SIZE_CAP_BYTES)
            .ok()?;
    let analysis: PackageAnalysis = serde_json::from_slice(&bytes).ok()?;
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

/// Atomically replace `.lpm-security.json` through a retained directory capability.
pub fn write_cached_analysis_atomic_in_dir(
    package_dir: &cap_std::fs::Dir,
    analysis: &PackageAnalysis,
) -> Result<(), std::io::Error> {
    use std::io::Write as _;

    let json = serde_json::to_string_pretty(analysis).map_err(std::io::Error::other)?;
    lpm_common::write_file_atomic_in_dir_with(
        package_dir,
        std::ffi::OsStr::new(".lpm-security.json"),
        |file| file.write_all(json.as_bytes()),
    )
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
    fn fingerprints_tell_a_left_out_runtime_file_from_a_left_out_test_file() {
        let analyze = |extra: &str| {
            let package = tempfile::tempdir().unwrap();
            let mut files: Vec<(String, &str)> = vec![
                ("package.json".into(), r#"{"name":"kit","license":"MIT"}"#),
                ("test/0000.js".into(), "eval(code)"),
                (extra.into(), "module.exports = 1"),
            ];
            files.extend(
                (0..MAX_FILES_PER_PACKAGE)
                    .map(|index| (format!("lib/{index:04}.js"), "module.exports = 1")),
            );
            files.extend(
                (1..MAX_FILES_PER_PACKAGE / 4)
                    .map(|index| (format!("test/{index:04}.js"), "module.exports = 1")),
            );
            for (path, content) in &files {
                let file_path = package.path().join(path);
                fs::create_dir_all(file_path.parent().unwrap()).unwrap();
                fs::write(file_path, content).unwrap();
            }
            let directory =
                cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                    .unwrap();
            let (analysis, fused) = analyze_package_from_open_dir_with_fingerprint(
                &directory,
                PackageDirectory::Published,
            );
            let standalone =
                package_input_fingerprint_from_open_dir(&directory, PackageDirectory::Published)
                    .unwrap();
            assert_eq!(fused.as_deref(), Some(standalone.as_str()), "{extra}");
            (analysis.source.eval, standalone)
        };

        // The same files are read either way; only the role of the one left out differs.
        let (runtime_eval, runtime_left_out) = analyze("lib/9999.js");
        let (test_eval, test_left_out) = analyze("test/9999.js");

        assert!(runtime_eval);
        assert!(!test_eval);
        assert_ne!(runtime_left_out, test_left_out);
    }

    fn nested_fingerprint_fixture(root: &Path) {
        let mut files: Vec<(String, String)> = vec![
            (
                "package.json".into(),
                r#"{"name":"nested","version":"1.0.0","main":"lib/index.js"}"#.into(),
            ),
            (
                "lib/index.js".into(),
                "module.exports = require('./deep/b');\n".into(),
            ),
            (
                "lib/deep/b.js".into(),
                "exports.b = () => eval('1');\n".into(),
            ),
            (
                "lib/deep/deeper/c.js".into(),
                "require('child_process');\n".into(),
            ),
            ("lib/deep/types.d.ts".into(), "export {};\n".into()),
            ("src/x.ts".into(), "export const x: number = 1;\n".into()),
            ("test/t.js".into(), "fetch('https://example.com');\n".into()),
            ("README.md".into(), "readme\n".into()),
        ];
        for index in 0..24 {
            files.push((
                format!("lib/many/dir-{index:02}/file.js"),
                format!("module.exports = {index};\n"),
            ));
        }
        for (path, content) in files {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
    }

    // The fingerprint hashes native paths, so Windows records `lib\index.js`.
    #[cfg(unix)]
    #[test]
    fn warm_fingerprint_of_a_nested_package_is_stable() {
        let package = tempfile::tempdir().unwrap();
        nested_fingerprint_fixture(package.path());
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();

        let fingerprint =
            package_input_fingerprint_from_open_dir(&directory, PackageDirectory::Published)
                .unwrap();

        assert_eq!(
            fingerprint,
            "sha256-b5bec034135c6c51bed7be72c440f035e96a9fdad24520f4508e0c50fb7166aa"
        );
    }

    #[test]
    fn package_dirs_open_nested_files_through_cached_directories() {
        let package = tempfile::tempdir().unwrap();
        nested_fingerprint_fixture(package.path());
        let root = cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
            .unwrap();
        let mut directories = PackageDirs::new(&root);

        for path in [
            "lib/deep/deeper/c.js",
            "lib/deep/b.js",
            "lib/index.js",
            "lib/deep/deeper/c.js",
            "package.json",
        ] {
            let (_, size) = directories.open_file(Path::new(path)).unwrap();
            assert_eq!(
                size,
                std::fs::metadata(package.path().join(path)).unwrap().len(),
                "{path}"
            );
        }
        for index in 0..24 {
            directories
                .open_file(Path::new(&format!("lib/many/dir-{index:02}/file.js")))
                .unwrap();
        }
        assert!(directories.chain.len() <= PackageDirs::MAX_HELD);
    }

    fn deep_package(root: &Path, depth: usize) -> std::path::PathBuf {
        let mut relative = std::path::PathBuf::new();
        for level in 0..depth {
            relative.push(format!("d{level}"));
        }
        std::fs::create_dir_all(root.join(&relative)).unwrap();
        relative.push("leaf.js");
        std::fs::write(root.join(&relative), "module.exports = 1;\n").unwrap();
        relative
    }

    #[test]
    fn package_dirs_hold_at_most_eight_directories_of_a_deep_path() {
        let package = tempfile::tempdir().unwrap();
        let leaf = deep_package(package.path(), 24);
        std::fs::write(package.path().join("top.js"), "1").unwrap();
        let root = cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
            .unwrap();
        let mut directories = PackageDirs::new(&root);

        directories.open_file(&leaf).unwrap();
        assert_eq!(directories.chain.len(), PackageDirs::MAX_HELD);
        directories.open_file(Path::new("top.js")).unwrap();
        directories.open_file(&leaf).unwrap();

        assert!(directories.chain.len() <= PackageDirs::MAX_HELD);
        directories.verify_unchanged().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn package_dirs_open_holding_one_directory_when_descriptors_run_out() {
        const CHILD: &str = "LPM_TEST_PACKAGE_DIRS_DESCRIPTOR_LIMIT";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "behavioral::tests::package_dirs_open_holding_one_directory_when_descriptors_run_out",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let package = tempfile::tempdir().unwrap();
        let leaf = deep_package(package.path(), 12);
        let root = cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
            .unwrap();
        // Leave four free descriptors: fewer than the chain would hold.
        let mut free = 0;
        let mut limit = 0;
        while free < 4 {
            // SAFETY: F_GETFD only reads the descriptor's flags.
            if unsafe { libc::fcntl(limit, libc::F_GETFD) } == -1 {
                free += 1;
            }
            limit += 1;
        }
        let mut original = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes the valid struct.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0
        );
        let lowered = libc::rlimit {
            rlim_cur: limit as libc::rlim_t,
            rlim_max: original.rlim_max,
        };
        // SAFETY: setrlimit reads the valid struct; this child process only
        // runs this test.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
        let mut directories = PackageDirs::new(&root);

        let (_file, size) = directories.open_file(&leaf).unwrap();

        assert_eq!(size, "module.exports = 1;\n".len() as u64);
        assert!(
            directories.chain.is_empty(),
            "the open ran out of descriptors and held one directory at a time"
        );
        // SAFETY: as above; restores the soft limit the test lowered.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) },
            0
        );
        directories.verify_unchanged().unwrap();
        let mut other_thread = PackageDirs::new(&root);
        other_thread.open_file(&leaf).unwrap();
        assert!(
            other_thread.chain.is_empty(),
            "once any reader ran out, no reader holds directories"
        );
    }

    #[test]
    fn a_test_file_the_open_directory_walk_fails_to_read_is_an_unread_test() {
        let package = tempfile::tempdir().unwrap();
        fs::write(
            package.path().join("package.json"),
            br#"{"name":"kit","license":"MIT"}"#,
        )
        .unwrap();
        fs::create_dir(package.path().join("tests")).unwrap();
        fs::write(package.path().join("tests/a.js"), b"module.exports = 1").unwrap();
        fs::write(package.path().join("tests/b.js"), b"eval(code)").unwrap();
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();
        // The first file opened grows past the full-read limit before it's read.
        let grown = package.path().join("tests/a.js");
        AFTER_FIRST_SOURCE_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::write(&grown, vec![b' '; MAX_FILE_SIZE as usize + 1]).unwrap();
            }));
        });

        let analysis = analyze_package_from_open_dir(&directory, PackageDirectory::Published);

        // An unread test leaves the package's code known, so the other test's
        // eval stays a test's.
        assert!(!analysis.source.eval);
        assert!(analysis.meta.test_only_tags.iter().any(|tag| tag == "eval"));
    }

    // Windows refuses to rename a directory a handle holds open, so a held
    // directory can't be replaced while its files are read there.
    #[cfg(unix)]
    #[test]
    fn fingerprints_are_dropped_when_a_directory_is_replaced_while_files_are_read() {
        for warm in [true, false] {
            let package = tempfile::tempdir().unwrap();
            nested_fingerprint_fixture(package.path());
            let directory =
                cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                    .unwrap();
            let displaced = tempfile::tempdir_in(package.path().parent().unwrap()).unwrap();
            let (root, old_lib) = (package.path().to_path_buf(), displaced.path().join("lib"));
            AFTER_FIRST_SOURCE_OPEN.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    std::fs::rename(root.join("lib"), old_lib).unwrap();
                    std::fs::create_dir(root.join("lib")).unwrap();
                }));
            });

            if warm {
                package_input_fingerprint_from_open_dir(&directory, PackageDirectory::Published)
                    .expect_err("a fingerprint of a directory replaced mid-read was kept");
            } else {
                let (analysis, fingerprint) = analyze_package_from_open_dir_with_fingerprint(
                    &directory,
                    PackageDirectory::Published,
                );
                assert!(
                    !analysis.source.eval && !analysis.source.child_process,
                    "the analysis must describe the replaced, now empty, lib/"
                );
                assert_eq!(
                    fingerprint,
                    Some(
                        package_input_fingerprint_from_open_dir(
                            &directory,
                            PackageDirectory::Published
                        )
                        .unwrap()
                    ),
                    "the package is read again by path and fingerprinted as it is now"
                );
            }
            assert!(AFTER_FIRST_SOURCE_OPEN.with(|hook| hook.borrow().is_none()));
        }
    }

    #[test]
    fn package_dirs_stop_tracking_and_holding_directories_past_their_limit() {
        let package = tempfile::tempdir().unwrap();
        for index in 0..6 {
            let directory = package.path().join(format!("lib/m{index}"));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("index.js"), format!("{index}")).unwrap();
        }
        let root = cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
            .unwrap();
        let mut directories = PackageDirs::with_tracking_limit(&root, 3);

        for index in 0..4 {
            directories
                .open_file(Path::new(&format!("lib/m{index}/index.js")))
                .unwrap();
        }
        let tracked = directories.opened.len();
        std::fs::rename(
            package.path().join("lib/m5"),
            package.path().join("lib/m5-old"),
        )
        .unwrap();
        std::fs::create_dir(package.path().join("lib/m5")).unwrap();
        std::fs::write(package.path().join("lib/m5/index.js"), "new").unwrap();
        let (_, size) = directories.open_file(Path::new("lib/m5/index.js")).unwrap();

        assert!((3..=4).contains(&tracked), "{tracked}");
        assert_eq!(
            directories.opened.len(),
            tracked,
            "past the limit nothing more is tracked"
        );
        assert!(
            directories.chain.is_empty(),
            "past the limit no handle is held"
        );
        assert_eq!(
            size, 3,
            "an untracked open reads the directory as it is now"
        );
        directories.verify_unchanged().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn package_dirs_verify_after_reads_with_one_descriptor_left() {
        const CHILD: &str = "LPM_TEST_PACKAGE_DIRS_VERIFY_LIMIT";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "behavioral::tests::package_dirs_verify_after_reads_with_one_descriptor_left",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let package = tempfile::tempdir().unwrap();
        let leaf = deep_package(package.path(), 12);
        let root = cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
            .unwrap();
        let mut directories = PackageDirs::new(&root);
        drop(directories.open_file(&leaf).unwrap());
        assert_eq!(directories.chain.len(), PackageDirs::MAX_HELD);
        let mut limit = 0;
        // SAFETY: F_GETFD only reads the descriptor's flags.
        while unsafe { libc::fcntl(limit, libc::F_GETFD) } != -1 {
            limit += 1;
        }
        // One free descriptor below the limit besides the held handles.
        let limit = limit + 1;
        let rlimit = libc::rlimit {
            rlim_cur: limit as libc::rlim_t,
            rlim_max: limit as libc::rlim_t,
        };
        // SAFETY: setrlimit reads the valid struct; this child process only
        // runs this test.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) }, 0);

        directories.verify_unchanged().unwrap();
    }

    #[test]
    fn package_dirs_detect_a_directory_replaced_after_it_was_opened() {
        let package = tempfile::tempdir().unwrap();
        nested_fingerprint_fixture(package.path());
        let root = cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
            .unwrap();
        let mut directories = PackageDirs::new(&root);
        directories
            .open_file(Path::new("lib/deep/deeper/c.js"))
            .unwrap();
        directories.open_file(Path::new("lib/index.js")).unwrap();
        directories.verify_unchanged().unwrap();

        std::fs::rename(
            package.path().join("lib/deep"),
            package.path().join("lib/old"),
        )
        .unwrap();
        std::fs::create_dir_all(package.path().join("lib/deep/deeper")).unwrap();
        std::fs::write(package.path().join("lib/deep/deeper/c.js"), "changed").unwrap();

        let error = directories.verify_unchanged().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other, "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn package_dirs_refuse_links_and_parent_components() {
        use std::os::unix::fs::symlink;

        let package = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.js"), "secret").unwrap();
        std::fs::create_dir_all(package.path().join("lib/real")).unwrap();
        std::fs::write(package.path().join("lib/real/a.js"), "a").unwrap();
        symlink(outside.path(), package.path().join("lib/escape")).unwrap();
        symlink(
            outside.path().join("secret.js"),
            package.path().join("lib/real/link.js"),
        )
        .unwrap();
        let root = cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
            .unwrap();
        let mut directories = PackageDirs::new(&root);
        directories.open_file(Path::new("lib/real/a.js")).unwrap();

        for path in [
            "lib/escape/secret.js",
            "lib/real/link.js",
            "lib/real/../escape/secret.js",
            "lib/real/..",
        ] {
            assert!(
                directories.open_file(Path::new(path)).is_err(),
                "{path} was opened"
            );
        }
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
            &mut Vec::new(),
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
                format!("x={}eval(y){};", "(a=".repeat(3_000), ")".repeat(3_000)),
            ),
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
    fn parenthesized_lists_nested_in_defaults_are_parsed_in_linear_time() {
        // A parenthesized list that may be arrow parameters must be parsed
        // once, not as parameters and then again as an expression with every
        // list nested in it.
        for (filename, open) in [
            ("index.js", "([,],a=y,b="),
            ("index.js", "({a=1}=y,b="),
            ("index.ts", "(a=y,b="),
        ] {
            let source = format!("x={};eval(y);", nested(open, "0", ")", 3_000));
            let flat = format!("{}eval(y);", "x;".repeat(source.len() / 2));
            let started = std::time::Instant::now();
            let flat_result = analyze_on_a_worker_stack(filename, flat);
            let flat_time = started.elapsed();
            let started = std::time::Instant::now();
            let result = analyze_on_a_worker_stack(filename, source);
            let nested_time = started.elapsed();
            assert_eq!(flat_result.unparsed_files, 0);
            assert!(result.source.eval);
            assert_eq!(result.unparsed_files, 0, "{filename} {open}");
            assert!(
                nested_time < flat_time * 5 + std::time::Duration::from_millis(200),
                "{filename} {open}: nested {nested_time:?}, flat {flat_time:?}"
            );
        }
    }

    #[test]
    fn expressions_in_more_wrappers_than_real_code_has_are_read_without_parsing_in_linear_time() {
        // The rules read through wrappers, and read an initializer again for
        // each reference to it.
        let analyze = |filename: &'static str, source: String| {
            std::thread::Builder::new()
                .stack_size(256 * 1024 * 1024)
                .spawn(move || {
                    let started = std::time::Instant::now();
                    let result = analyze_bytes(filename, source.as_bytes());
                    (result, started.elapsed())
                })
                .unwrap()
                .join()
                .unwrap()
        };
        let depth = 10_000;
        let references = 20_000;
        let parenthesized = nested("(", "function(){}", ")", depth);
        for (filename, source) in [
            (
                "index.js",
                format!(
                    "eval(y);const f={parenthesized};{}",
                    "f();".repeat(references)
                ),
            ),
            (
                "index.js",
                format!(
                    "eval(y);const f={parenthesized};var x;{}",
                    "x=f;".repeat(references)
                ),
            ),
            (
                "index.ts",
                format!(
                    "eval(y);const f=function(){{}}{};{}",
                    "!".repeat(depth),
                    "f();".repeat(references)
                ),
            ),
        ] {
            let flat = format!("{}eval(y);", "x;".repeat(source.len() / 2));
            let (flat_result, flat_time) = analyze(filename, flat);
            let (result, nested_time) = analyze(filename, source);
            assert_eq!(flat_result.unparsed_files, 0);
            assert!(result.source.eval);
            assert_eq!(result.unparsed_files, 1, "{filename}");
            assert!(
                nested_time < flat_time * 5 + std::time::Duration::from_millis(200),
                "{filename}: nested {nested_time:?}, flat {flat_time:?}"
            );
        }
    }

    #[test]
    fn expressions_in_as_many_wrappers_as_real_code_could_have_are_parsed() {
        // A run of wrappers continues only into the expression a wrapper
        // wraps, and into the last expression of a sequence, as the rules read
        // through them.
        for (filename, source, unparsed) in [
            (
                "index.js",
                format!("x={};", nested("(", "eval(y)", ")", 32)),
                0,
            ),
            (
                "index.js",
                format!("x={};", nested("(", "eval(y)", ")", 33)),
                1,
            ),
            (
                "index.js",
                format!("x={};", nested("(", "eval(y)", ",0)", 40)),
                0,
            ),
            (
                "index.js",
                format!("x={};", nested("(0,", "eval(y)", ")", 40)),
                1,
            ),
            (
                "index.ts",
                format!("x=a as {{[{}]:number}};eval(y);", nested("(", "k", ")", 32)),
                0,
            ),
            ("index.ts", format!("x=a{};eval(y);", " as T".repeat(33)), 1),
            (
                "index.ts",
                format!("x=a{};eval(y);", " satisfies T".repeat(33)),
                1,
            ),
            ("index.ts", format!("x={}a;eval(y);", "<T>".repeat(33)), 1),
            ("index.ts", format!("x=a{};eval(y);", "!".repeat(33)), 1),
            (
                "index.ts",
                format!("x={};eval(y);", nested("(", "a<T>", ")", 31)),
                0,
            ),
            (
                "index.ts",
                format!("x={};eval(y);", nested("(", "a<T>", ")", 32)),
                1,
            ),
        ] {
            let result = analyze_on_a_worker_stack(filename, source.clone());
            assert!(result.source.eval);
            assert_eq!(result.unparsed_files, unparsed, "{source}");
        }
    }

    #[test]
    fn code_after_a_top_level_await_parsed_again_is_analyzed() {
        // Found to be a module, each source's statement that starts with
        // `await` ends earlier than its script reading did, and the code after
        // it runs.
        for source in [
            "await / a; x = /;0/ + eval(y);\nexport {};\n",
            "await /a/\neval(y)\nexport {};\n",
        ] {
            let result = analyze_on_a_worker_stack("index.js", source.to_owned());
            assert_eq!(result.unparsed_files, 0, "{source}");
            assert!(result.source.eval, "{source}");
        }
    }

    #[test]
    fn a_source_in_too_many_wrappers_keeps_its_comments_and_literals_masked() {
        let source = format!("/* eval(y) */x='eval(y)';x={};", nested("(", "a", ")", 33));
        let result = analyze_on_a_worker_stack("index.js", source);
        assert_eq!(result.unparsed_files, 1);
        assert!(!result.source.eval);
    }

    #[test]
    fn generic_arrow_heads_nested_in_defaults_are_read_without_parsing_in_linear_time() {
        // A TypeScript `<` that may open a generic arrow function is parsed
        // as one and, when no `=>` follows its parameters, parsed again as a
        // type assertion, with every head nested in its defaults.
        let source = format!("x={};eval(y);", nested("<T>(a=y,b=", "0", ")", 3_000));
        assert!(syntax::exhausts_the_speculation_budget("index.ts", &source));
        let flat = format!("{}eval(y);", "x;".repeat(source.len() / 2));
        let started = std::time::Instant::now();
        let flat_result = analyze_on_a_worker_stack("index.ts", flat);
        let flat_time = started.elapsed();
        let started = std::time::Instant::now();
        let result = analyze_on_a_worker_stack("index.ts", source);
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
    fn async_arrow_heads_that_mention_await_nested_in_defaults_are_read_without_parsing_in_linear_time()
     {
        // The arguments of an `async(…)` that mention `await` are parsed
        // again as parameters when `=>` follows, with every head nested in
        // their defaults.
        let source = format!(
            "x={};eval(y);",
            nested("async(a=", "await 0", ")=>0", 3_000)
        );
        assert!(syntax::exhausts_the_speculation_budget("index.js", &source));
        let flat = format!("{}eval(y);", "x;".repeat(source.len() / 2));
        let started = std::time::Instant::now();
        let flat_result = analyze_on_a_worker_stack("index.js", flat);
        let flat_time = started.elapsed();
        let started = std::time::Instant::now();
        let result = analyze_on_a_worker_stack("index.js", source);
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
    fn arrow_heads_after_many_lexer_errors_are_analyzed_in_linear_time() {
        // A checkpoint taken at each parenthesized list that may be arrow
        // parameters must not copy every diagnostic the lexer has recorded.
        for (filename, head) in [
            ("index.js", "(a,b)=>0;"),
            ("index.js", "(a,b);"),
            ("index.ts", "(a,b);"),
        ] {
            let source = format!(
                "{}{}eval(y);",
                "\"\\xZ\";".repeat(16_000),
                head.repeat(16_000)
            );
            let flat = format!("{}eval(y);", "x;".repeat(source.len() / 2));
            let started = std::time::Instant::now();
            let flat_result = analyze_on_a_worker_stack(filename, flat);
            let flat_time = started.elapsed();
            let started = std::time::Instant::now();
            let result = analyze_on_a_worker_stack(filename, source);
            let errors_time = started.elapsed();
            assert_eq!(flat_result.unparsed_files, 0);
            assert!(result.source.eval);
            assert!(
                errors_time < flat_time * 5 + std::time::Duration::from_millis(200),
                "{filename} {head}: lexer errors {errors_time:?}, flat {flat_time:?}"
            );
        }
    }

    #[test]
    fn long_tokens_read_again_by_nested_speculation_count_toward_the_parse_budget() {
        // Each enclosing generic arrow head parsed again reads the string
        // again: the budget counts bytes, not tokens.
        let source = format!(
            "x={};",
            nested(
                "<T>(a=",
                &format!("\"{}\"", "a".repeat(256 * 1024)),
                ")",
                2_000
            )
        );
        assert!(syntax::exhausts_the_speculation_budget("index.ts", &source));
        let flat = format!("{}eval(y);", "x;".repeat(source.len() / 2));
        let started = std::time::Instant::now();
        let flat_result = analyze_on_a_worker_stack("index.ts", flat);
        let flat_time = started.elapsed();
        let started = std::time::Instant::now();
        let result = analyze_on_a_worker_stack("index.ts", source);
        let nested_time = started.elapsed();
        assert_eq!(flat_result.unparsed_files, 0);
        assert_eq!(result.unparsed_files, 1);
        assert!(
            nested_time < flat_time * 5 + std::time::Duration::from_millis(200),
            "nested {nested_time:?}, flat {flat_time:?}"
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
        // One pass takes about 3 times as long as a single addon, up to 8
        // times on a loaded CI runner. A search per addon took over 1,000
        // times as long, about 20 seconds.
        assert!(
            many < one * 50 + std::time::Duration::from_secs(1),
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
    fn a_peer_dependency_an_install_adds_sets_the_git_and_http_tags() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT",
                    "peerDependencies":{"helper":"github:owner/helper","mirror":"http://example.com/m.tgz"}}"#,
            ),
            ("index.js", b"module.exports = 1"),
        ]);

        assert!(analysis.manifest.git_dependency);
        assert!(analysis.manifest.http_dependency);
    }

    #[test]
    fn a_peer_npm_reads_as_optional_by_any_true_value_sets_no_dependency_tag() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"plugin","license":"MIT",
                    "peerDependencies":{"a":"github:owner/a","b":"github:owner/b"},
                    "peerDependenciesMeta":{"a":{"optional":1},"b":{"optional":"yes"}}}"#,
            ),
            ("index.js", b"module.exports = 1"),
        ]);

        assert!(!analysis.manifest.git_dependency);
    }

    #[test]
    fn optional_peers_and_any_version_peer_ranges_set_no_dependency_tag() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"plugin","license":"MIT",
                    "peerDependencies":{"eslint":"*","react":"","helper":"github:owner/helper"},
                    "peerDependenciesMeta":{"helper":{"optional":true}}}"#,
            ),
            ("index.js", b"module.exports = 1"),
        ]);

        assert!(!analysis.manifest.wildcard_dependency);
        assert!(!analysis.manifest.git_dependency);
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
        // As lpm-store feeds an extraction: each buffered file's bytes, and
        // every other file from disk.
        let mut streaming = PackageAnalyzer::new();
        for (path, content) in files.iter().rev() {
            let path = Path::new(path);
            streaming.note_entry(path);
            if PackageAnalyzer::should_buffer_source(path, content.len() as u64) {
                streaming.feed(path, content);
            } else {
                streaming.feed_oversized_source_file(
                    path,
                    &package.path().join(path),
                    content.len() as u64,
                );
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
        // Fields the serialized form leaves out.
        for other in [&by_capability, &streamed] {
            assert_eq!(
                other.meta.runtime_test_files,
                by_path.meta.runtime_test_files
            );
            assert_eq!(
                other.meta.runtime_unparsed_files,
                by_path.meta.runtime_unparsed_files
            );
        }
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
    fn a_test_file_the_package_code_requires_counts_as_runtime() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","main":"index.js"}"#,
            ),
            ("index.js", br#"module.exports = require("./tests/run.js")"#),
            (
                "tests/run.js",
                br#"require("child_process").exec(command); eval(code)"#,
            ),
            ("tests/unrelated.test.js", b"fetch(url)"),
        ]);

        assert!(analysis.source.child_process);
        assert!(analysis.source.eval);
        assert!(!analysis.source.network);
        assert_eq!(analysis.meta.test_only_tags, ["network"]);
        assert!(!analysis.meta.tag_files["eval"].tests_only);
    }

    #[test]
    fn the_analysis_lists_the_test_files_that_count_as_package_code_without_storing_them() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","main":"index.js"}"#,
            ),
            ("index.js", br#"require("./test/helper")"#),
            ("test/helper.js", br#"require("./support")"#),
            ("test/support.js", b"module.exports = 1"),
            ("test/unrelated.test.js", b"eval(code)"),
        ]);

        assert_eq!(
            analysis.meta.runtime_test_files,
            [Path::new("test/helper.js"), Path::new("test/support.js")]
        );
        assert!(
            serde_json::to_value(&analysis).unwrap()["meta"]
                .get("runtimeTestFiles")
                .is_none()
        );
    }

    #[test]
    fn the_analysis_counts_the_unparsed_files_of_package_code_apart() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","main":"index.js"}"#,
            ),
            ("index.js", b"module.exports = 1"),
            ("lib/broken.js", b"function ("),
            ("tests/broken.js", b"function ("),
        ]);
        assert_eq!(analysis.meta.unparsed_files, 2);
        assert_eq!(analysis.meta.runtime_unparsed_files, 1);

        let reached = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","main":"index.js"}"#,
            ),
            ("index.js", br#"require("./tests/broken.js")"#),
            ("tests/broken.js", b"function ("),
        ]);
        assert_eq!(reached.meta.unparsed_files, 1);
        assert_eq!(reached.meta.runtime_unparsed_files, 1);
    }

    #[cfg(unix)]
    #[test]
    fn the_listed_test_files_keep_names_that_are_not_utf8_exactly() {
        use std::os::unix::ffi::OsStrExt;
        let not_utf8 = Path::new(std::ffi::OsStr::from_bytes(b"test/r\xffn.js"));
        let replacement = Path::new("test/r\u{FFFD}n.js");
        let backslash = Path::new("test/a\\b.js");
        let mut streaming = PackageAnalyzer::new();
        let files: [(&Path, &[u8]); 5] = [
            (
                Path::new("package.json"),
                br#"{"name":"kit","license":"MIT"}"#,
            ),
            (Path::new("index.js"), b"require(pick())"),
            (not_utf8, b"eval(code)"),
            (replacement, b"eval(code)"),
            (backslash, b"eval(code)"),
        ];
        for (path, content) in files {
            streaming.note_entry(path);
            if PackageAnalyzer::should_buffer_source(path, content.len() as u64) {
                streaming.feed(path, content);
            }
        }
        let package = tempfile::tempdir().unwrap();
        let analysis = streaming.finalize(package.path());

        let mut listed = analysis.meta.runtime_test_files;
        listed.sort();
        let mut expected = vec![
            not_utf8.to_path_buf(),
            replacement.to_path_buf(),
            backslash.to_path_buf(),
        ];
        expected.sort();
        assert_eq!(listed, expected);
    }

    #[test]
    fn a_test_file_reached_through_other_test_files_counts_as_runtime() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            (
                "lib/index.js",
                br#"import helper from "../test/helper"; export default helper"#,
            ),
            (
                "test/helper.js",
                br#"module.exports = require("./support")"#,
            ),
            ("test/support/index.js", b"eval(code)"),
        ]);

        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn a_test_file_the_package_code_starts_as_a_process_counts_as_runtime() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            (
                "index.js",
                br#"const path = require("path"); require("child_process").fork(path.join(__dirname, "__tests__/run.js")); require("child_process").execSync("node spec/setup.js")"#,
            ),
            ("__tests__/run.js", b"eval(code)"),
            ("spec/setup.js", b"fetch(url)"),
        ]);

        assert!(analysis.source.eval);
        assert!(analysis.source.network);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn a_computed_require_in_package_code_keeps_every_test_file_runtime() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            (
                "index.js",
                br#"const path = require("path"); module.exports = name => require(path.join(__dirname, "tests", name))"#,
            ),
            ("tests/run.js", b"eval(code)"),
        ]);

        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn a_test_file_an_exports_pattern_matches_counts_as_runtime() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","exports":{".":"./index.js","./*":"./tests/*.js"}}"#,
            ),
            ("index.js", b"module.exports = 1"),
            ("tests/run.js", b"eval(code)"),
        ]);

        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn a_test_file_package_code_that_does_not_parse_requires_counts_as_runtime() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", br#"require('./tests/run.js'); )("#),
            ("tests/run.js", b"eval(code)"),
        ]);

        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn package_code_a_budget_leaves_unread_keeps_every_test_file_runtime() {
        let mut analyzer = PackageAnalyzer::with_limits(ScanLimits {
            files: 1,
            ..ScanLimits::INSTALL
        });
        analyzer.feed(Path::new("index.js"), b"module.exports = 1");
        analyzer.feed(Path::new("lib/unread.js"), br#"require("../test/run")"#);
        analyzer.feed(Path::new("test/run.js"), b"eval(code)");
        let analysis = analyzer.finish(Some(br#"{"name":"kit","license":"MIT"}"#));

        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn sampled_package_code_keeps_every_test_file_runtime() {
        let mut analyzer = PackageAnalyzer::with_limits(ScanLimits {
            full_file_bytes: 64,
            sample_bytes: 16,
            ..ScanLimits::INSTALL
        });
        let bundle = format!("module.exports = 1;{}", " ".repeat(200));
        analyzer.feed(Path::new("dist/bundle.js"), bundle.as_bytes());
        analyzer.feed(Path::new("test/run.js"), b"eval(code)");
        let analysis = analyzer.finish(Some(br#"{"name":"kit","license":"MIT"}"#));

        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    /// Whether `tests/run.js` (which calls `eval`) counts as package code when
    /// `index.js` holds `code`, across every scan path.
    fn reaches_tests_run(code: &str, manifest: &str) -> bool {
        let analysis = analyze_every_way(&[
            ("package.json", manifest.as_bytes()),
            ("index.js", code.as_bytes()),
            ("tests/run.js", b"eval(code)"),
        ]);
        assert_eq!(
            analysis.source.eval,
            analysis.meta.test_only_tags.is_empty(),
            "{code}"
        );
        analysis.source.eval
    }

    #[test]
    fn package_code_reaches_a_test_file_through_common_path_idioms() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"require("./te" + "sts/run.js")"#,
            r#"import("./te" + `sts/run.js`)"#,
            r#"const cp = require("child_process"); cp.fork(__dirname + "/tests/run.js")"#,
            r#"const cp = require("child_process"); cp.fork(`${__dirname}/tests/run.js`)"#,
            r#"const path = require("path"); require("child_process").fork(path.join(__dirname, "tests", "run.js"))"#,
            r#"import "./tests/run.js?v=1""#,
            r#"import "./tests/run.js#x""#,
            r#"import "./t%65sts/run.js""#,
            r#"require("./Tests/run.js")"#,
            r#"require(".\\tests\\run.js")"#,
            r#"require("child_process").execSync("node tests/run.js|cat")"#,
            r#"require("child_process").execSync("node tests/run.js&&true")"#,
            r#"require("child_process").execSync("cd tests && node run.js")"#,
            r#"require("child_process").fork("./tests/" + name)"#,
            r#"require("../kit/tests/run.js")"#,
            r#"require("kit/tests/run.js")"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
        assert!(reaches_tests_run(
            r##"require("#t/run")"##,
            r##"{"name":"kit","license":"MIT","imports":{"#t/*":"./tests/*.js"}}"##
        ));
        assert!(reaches_tests_run(
            "module.exports = 1",
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"node tests/[r]un.js"}}"#
        ));
        assert!(reaches_tests_run(
            "module.exports = 1",
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"node tests/?un.js"}}"#
        ));
    }

    #[test]
    fn a_computed_script_path_in_a_fork_or_worker_keeps_every_test_file_runtime() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"const cp = require("child_process"); cp.fork(pick())"#,
            r#"const { Worker } = require("worker_threads"); new Worker(pick())"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
    }

    #[test]
    fn a_script_of_another_language_an_install_script_runs_keeps_every_test_file_runtime() {
        for manifest in [
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"sh setup.sh"}}"#,
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"sh scripts/setup"}}"#,
        ] {
            assert!(
                reaches_tests_run("module.exports = 1", manifest),
                "{manifest}"
            );
        }
        // A path fragment a filter compares against names no file.
        assert!(!reaches_tests_run(
            r#"module.exports = file => file.includes("/tests/")"#,
            r#"{"name":"kit","license":"MIT"}"#
        ));
        // A browser Web Worker loads a URL, not a package file.
        assert!(!reaches_tests_run(
            "const worker = new global.Worker(URL.createObjectURL(blob))",
            r#"{"name":"kit","license":"MIT"}"#
        ));
    }

    #[test]
    fn a_relative_require_from_a_mixed_case_directory_reaches_a_test_file() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("Lib/index.js", br#"require("./tests/run.js")"#),
            ("Lib/tests/run.js", b"eval(code)"),
        ]);
        assert!(analysis.source.eval);
    }

    #[test]
    fn only_a_worker_threads_worker_with_a_computed_script_keeps_every_test_file_runtime() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        assert!(reaches_tests_run(
            r#"const W = require("worker_threads").Worker; new W(pick())"#,
            KIT
        ));
        assert!(!reaches_tests_run(
            r#"class Worker { constructor(options) {} } new Worker(pick())"#,
            KIT
        ));
    }

    #[test]
    fn an_install_script_runs_a_script_it_hands_to_a_shell_but_not_one_it_echoes() {
        assert!(!reaches_tests_run(
            "module.exports = 1",
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"echo setup.sh"}}"#
        ));
        assert!(reaches_tests_run(
            "module.exports = 1",
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"FOO=1 bash -e ./setup.sh"}}"#
        ));
    }

    #[test]
    fn a_shebang_line_says_which_runtime_runs_a_script_without_an_extension() {
        for (head, extension) in [
            (&b"#!/usr/bin/env node\nmain()"[..], Some("js")),
            (b"#!/usr/bin/node", Some("js")),
            (b"#! /usr/local/bin/node --harmony\r\n", Some("js")),
            (
                b"#!/usr/bin/env -S node --experimental-vm-modules\n",
                Some("js"),
            ),
            (b"#!/usr/bin/env NODE_ENV=production node\n", Some("js")),
            (b"#!/usr/bin/env nodejs\n", Some("js")),
            (b"#!/usr/bin/env bun\n", Some("js")),
            (b"#!/usr/bin/env -S deno run --allow-all\n", Some("ts")),
            (b"#!/usr/bin/env tsx\n", Some("ts")),
            (b"#!/usr/bin/env ts-node\n", Some("ts")),
            (b"#!/usr/bin/env -S -u DEBUG node\n", Some("js")),
            (b"#!/usr/bin/env --chdir /tmp node\n", Some("js")),
            (b"#!/usr/bin/env npx tsx\n", Some("ts")),
            (b"#!/usr/bin/env npx --yes ts-node\n", Some("ts")),
            (b"#!/usr/bin/env bunx tsx\n", Some("ts")),
            (b"#!/usr/local/bin/node20\n", Some("js")),
            (b"#!/usr/bin/env node-18\n", Some("js")),
            (b"#!C:/nodejs/node.exe\n", Some("js")),
            (b"#!/usr/bin/env node.exe\n", Some("js")),
            (b"#!/usr/bin/env zx\n", Some("js")),
            (b"\xEF\xBB\xBF#!/usr/bin/env node\n", Some("js")),
            (b"#!/usr/bin/env npx cowsay\n", None),
            (b"#!/bin/sh\nnode cli.js", None),
            (b"#!/usr/bin/env python3\n", None),
            (b"// #!/usr/bin/env node\n", None),
            (b"MIT License", None),
            (b"", None),
        ] {
            assert_eq!(
                shebang_script_extension(head),
                extension,
                "{}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[test]
    fn a_script_without_an_extension_is_read_as_source_when_its_shebang_line_runs_node() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","bin":{"kit":"bin/cli"}}"#,
            ),
            ("bin/cli", b"#!/usr/bin/env node\neval(process.argv[2]);\n"),
            (
                "LICENSE",
                b"Permission is granted to require('child_process').exec(anything).",
            ),
            (
                "scripts/fetch",
                b"#!/bin/sh\nfetch('https://example.com')\n",
            ),
            ("bin/run", b"#!/usr/bin/env tsx\nconst port: number = 1;\n"),
        ]);
        assert!(analysis.source.eval);
        assert!(!analysis.source.child_process);
        assert!(!analysis.source.network);
        assert_eq!(analysis.meta.unparsed_files, 0);
    }

    #[test]
    fn a_script_with_an_unknown_or_empty_extension_is_read_when_its_shebang_line_runs_node() {
        let mut files: Vec<(&str, &[u8])> = vec![
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","bin":{"kit":"bin/cli.sh","run":"bin/run."}}"#,
            ),
            (
                "bin/cli.sh",
                b"#!/usr/bin/env node\neval(process.argv[2]);\n",
            ),
            (
                "docs/usage.md",
                b"#!/usr/bin/env node\nrequire('child_process').exec(anything);\n",
            ),
        ];
        // Windows drops a trailing dot from a file name, so no such file exists there.
        if cfg!(not(windows)) {
            files.push((
                "bin/run.",
                b"#!/usr/bin/env node\nfetch('https://example.com');\n",
            ));
        }
        let analysis = analyze_every_way(&files);
        assert!(analysis.source.eval);
        assert_eq!(analysis.source.network, cfg!(not(windows)));
        assert!(!analysis.source.child_process);
    }

    #[cfg(unix)]
    #[test]
    fn reads_as_source_turns_down_a_fifo_without_waiting_for_a_writer() {
        let package = tempfile::tempdir().unwrap();
        let fifo = package.path().join("cli");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `path` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(PackageAnalyzer::reads_as_source(Path::new("cli"), &fifo));
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(false)
        );
    }

    #[test]
    fn a_test_file_a_bin_script_without_an_extension_reaches_counts_as_runtime() {
        let analysis = analyze_every_way(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","bin":{"kit":"bin/cli"}}"#,
            ),
            (
                "bin/cli",
                b"#!/usr/bin/env node\nrequire('../test/helper.js');\n",
            ),
            ("test/helper.js", b"eval(code)"),
        ]);
        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn an_oversized_script_without_an_extension_is_sampled_in_every_walk() {
        let mut script = b"#!/usr/bin/env node\neval(process.argv[2]);\n".to_vec();
        script.resize(MAX_FILE_SIZE as usize + 1, b' ');
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("bin/cli", &script),
        ]);
        assert!(analysis.source.eval);
        assert_eq!(analysis.meta.oversized_source_files.len(), 1);
    }

    #[test]
    fn a_cyclic_alias_of_a_constructor_is_analysed_without_unbounded_recursion() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", b"var a = b, b = a; new a(pick()); eval(code)"),
        ]);
        assert!(analysis.source.eval);
        assert!(analysis.meta.unparsed_files == 0);
    }

    fn padded_exports(extra: &str) -> String {
        let exports: Vec<String> = (0..300)
            .map(|index| format!(r#""./feature-{index}":"./lib/feature-{index}.js""#))
            .collect();
        format!(
            r#"{{"name":"kit","license":"MIT","exports":{{{}}}{extra}}}"#,
            exports.join(",")
        )
    }

    #[test]
    fn a_large_manifest_keeps_its_paths_or_counts_every_test_file() {
        for extra in [
            r#","scripts":{"postinstall":"cd tests && node run.js"}"#,
            r#","main":"./tests/./run.js""#,
        ] {
            let manifest = padded_exports(extra);
            assert!(
                reaches_tests_run("module.exports = 1", &manifest),
                "{extra}"
            );
        }
        assert!(!reaches_tests_run(
            "module.exports = 1",
            &padded_exports(r#","scripts":{"postinstall":"node lib/setup.js"}"#)
        ));
    }

    #[test]
    fn a_directory_part_of_a_built_path_names_the_test_files_in_it() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"require("child_process").execSync("node " + __dirname + "/tests/" + file)"#,
            r#"require("child_process").execSync(`node ${__dirname}/tests/${file}`)"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
        assert!(!reaches_tests_run(
            r#"if (file.includes("/tests/")) skip(file)"#,
            KIT
        ));
    }

    #[test]
    fn install_scripts_reach_a_test_file_through_wrappers_separators_and_interpreters() {
        let manifest =
            |scripts: &str| format!(r#"{{"name":"kit","license":"MIT","scripts":{{{scripts}}}}}"#);
        for scripts in [
            r#""postinstall":"true\nsh setup.sh""#,
            r#""postinstall":"exec ./setup.sh""#,
            r#""postinstall":"env bash scripts/setup""#,
            r#""postinstall":"./setup""#,
            r#""postinstall":"make""#,
            r#""postinstall":"FOO=1 npm run build","build":"node tests/run.js""#,
            r#""postinstall":"cross-env A=1 npm run build","build":"node tests/run.js""#,
            r#""postinstall":"(npm run build)","build":"node tests/run.js""#,
            r#""postinstall":"npm --prefix . run build","build":"node tests/run.js""#,
            r#""postinstall":"node -e \"require('./te'+'sts/run.js')\"""#,
            r#""postinstall":"node $npm_package_config_entry""#,
            r#""postinstall":"node tests""#,
        ] {
            assert!(
                reaches_tests_run("module.exports = 1", &manifest(scripts)),
                "{scripts}"
            );
        }
        for scripts in [
            r#""postinstall":"echo skipping tests""#,
            r#""postinstall":"node scripts/build.js && echo NODE_ENV=test""#,
        ] {
            assert!(
                !reaches_tests_run("module.exports = 1", &manifest(scripts)),
                "{scripts}"
            );
        }
    }

    #[test]
    fn worker_threads_workers_however_they_are_bound_keep_every_test_file_runtime() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"import("node:worker_threads").then(({ Worker }) => new Worker(pick()))"#,
            r#"const { Worker } = require("worker_threads"); class Pool extends Worker {} new Pool(pick())"#,
            r#"const { Worker } = require("worker_threads"); new Worker("require('./te' + 'sts/run.js')", { eval: true })"#,
            r#"new (process.getBuiltinModule("worker_threads").Worker)(pick())"#,
            r#"let W; W = require("worker_threads").Worker; new W(pick())"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
        assert!(!reaches_tests_run(
            "const worker = new Worker(pick()); worker.postMessage(1)",
            KIT
        ));
    }

    #[test]
    fn module_loads_through_require_as_a_value_keep_every_test_file_runtime() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            "require.bind(null)(pick())",
            "Reflect.apply(require, null, [pick()])",
            "const load = require; load(pick())",
            "[pick()].map(require)",
            r#"const cp = require("child_process"); cp.fork.call(null, pick())"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
        for code in [
            r#"if (typeof require === "function") module.exports = 1"#,
            "if (require.main === module) main()",
            "const resolved = require.resolve(pick())",
        ] {
            assert!(!reaches_tests_run(code, KIT), "{code}");
        }
    }

    #[test]
    fn code_a_launch_or_a_loader_preloads_from_a_computed_name_keeps_every_test_file_runtime() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"require("child_process").fork("./child.js", [], { execArgv: ["--require", pick()] })"#,
            r#"require("child_process").fork("./child.js", { execArgv: ["--import", pick()] })"#,
            r#"require("child_process").fork("./child.js", [], { env: { ...process.env, NODE_OPTIONS: "--require " + pick() } })"#,
            r#"const options = { execArgv: ["--require", pick()] }; require("child_process").fork(require("path").join(__dirname, "child.js"), [], options)"#,
            r#"const { Worker } = require("worker_threads"); new Worker("./child.js", { execArgv: ["--require", pick()] })"#,
            r#"process.getBuiltinModule("module").createRequire(__filename)(pick())"#,
            r#"require("module").register(pick(), require("url").pathToFileURL(__filename))"#,
            r#"require("module").prototype.require.call(module, pick())"#,
            r#"require.extensions[".js"](module, pick())"#,
            "process.mainModule.constructor._load(pick())",
            "require.main.constructor._load(pick())",
            r#"module._compile(require("fs").readFileSync(pick(), "utf8"), "x.js")"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
        // Flags spelled out, or inherited from how the package was started.
        for code in [
            r#"require("child_process").fork("./child.js", [], { execArgv: process.execArgv.filter(Boolean), env: { ...process.env, NODE_OPTIONS: "--max-old-space-size=4096" } })"#,
            r#"const { Worker } = require("worker_threads"); new Worker("./child.js", { execArgv: ["--enable-source-maps"] })"#,
            r#"const args = ["--verbose"]; require("child_process").fork(require("path").join(__dirname, "child.js"), args)"#,
        ] {
            assert!(!reaches_tests_run(code, KIT), "{code}");
        }
    }

    #[test]
    fn a_preload_flag_names_its_file_with_or_without_an_equals_sign() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"require("child_process").fork("./child.js", [], { execArgv: ["--require", "./tests/run.js"] })"#,
            r#"require("child_process").fork("./child.js", [], { execArgv: ["--require=./tests/run.js"] })"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
    }

    /// Whether `eval` in a test file counts as the package's own, the files given.
    fn eval_counts_as_package_code(files: &[(&str, &str)]) -> bool {
        let files: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(path, content)| (*path, content.as_bytes()))
            .collect();
        let analysis = analyze_every_way(&files);
        assert_eq!(
            analysis.source.eval,
            analysis.meta.test_only_tags.is_empty(),
            "{files:?}"
        );
        analysis.source.eval
    }

    #[test]
    fn package_code_reaches_a_test_file_back_through_its_own_name_or_a_bundled_module() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        const SCOPED: &str = r#"{"name":"@scope/kit","license":"MIT"}"#;
        for files in [
            [
                ("package.json", KIT),
                ("index.js", "require('../../node_modules/kit/tests/run.js')"),
                ("tests/run.js", "eval(code)"),
            ]
            .as_slice(),
            &[
                ("package.json", SCOPED),
                ("index.js", "require('../kit/tests/run.js')"),
                ("tests/run.js", "eval(code)"),
            ],
            &[
                ("package.json", SCOPED),
                ("index.js", "require('../../@scope/kit/tests/run.js')"),
                ("tests/run.js", "eval(code)"),
            ],
            &[
                ("package.json", KIT),
                ("index.js", "require('test')"),
                ("node_modules/test/index.js", "eval(code)"),
            ],
            &[
                ("package.json", KIT),
                ("index.js", "require('./test/a.js')"),
                ("test/a.js", "require('foo')"),
                ("test/node_modules/foo/index.js", "eval(code)"),
            ],
        ] {
            assert!(eval_counts_as_package_code(files), "{files:?}");
        }
        // A module the package doesn't bundle reaches nothing.
        assert!(!eval_counts_as_package_code(&[
            ("package.json", KIT),
            ("index.js", "require('react'); require('test')"),
            ("tests/run.js", "eval(code)"),
        ]));
    }

    #[test]
    fn install_scripts_are_read_as_the_shell_reads_them() {
        let manifest = |script: &str| {
            format!(
                r#"{{"name":"kit","license":"MIT","scripts":{{"postinstall":{}}}}}"#,
                serde_json::to_string(script).unwrap()
            )
        };
        // Quotes and escapes the shell joins.
        for script in [
            r#"node te''sts/run.js"#,
            r#"node te\sts/run.js"#,
            r#"node "te"sts/run.js"#,
        ] {
            assert!(
                reaches_tests_run("module.exports = 1", &manifest(script)),
                "{script}"
            );
        }
        // A script whose words a command computes, or that node reads from
        // its input.
        for script in [
            "node `echo te`sts/run.js",
            "node $(echo tests/run.js)",
            "node < scripts/data.txt",
        ] {
            assert!(
                reaches_tests_run("module.exports = 1", &manifest(script)),
                "{script}"
            );
        }
        assert!(!reaches_tests_run(
            "module.exports = 1",
            &manifest("node scripts/build.js < scripts/data.txt")
        ));
    }

    #[test]
    fn working_directories_set_away_from_the_launch_still_apply() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"const options = { cwd: "lib" }; require("child_process").fork("boot.test.js", options)"#,
            r#"const { chdir } = process; chdir("lib"); require("child_process").fork("./boot.test.js")"#,
        ] {
            assert!(reaches_lib_boot_test("index.js", code, KIT), "{code}");
        }
        for code in [
            r#"require("child_process").fork("run.js", { cwd: pick() })"#,
            r#"const options = makeOptions(); require("child_process").fork("run.js", options)"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
    }

    #[test]
    fn a_script_path_counts_as_static_only_when_built_from_known_path_functions() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"require("child_process").fork(["tests", "run.js"].join("/"))"#,
            r#"require("child_process").fork(pick().normalize())"#,
            r#"var __filename = pick(); require("child_process").fork(__filename)"#,
            r#"function start(__dirname) { require("child_process").fork(__dirname + "/x.js") }"#,
            r#"require("child_process").fork(...args)"#,
            r#"const { Worker } = require("worker_threads"); new Worker(...args)"#,
            "require(...args)",
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
        for code in [
            r#"const path = require("path"); require("child_process").fork(path.join(__dirname, "lib", "x.js"))"#,
            r#"const { join } = require("node:path"); require("child_process").fork(join(__dirname, "x.js"))"#,
            r#"require("child_process").fork(require.resolve("./lib/x.js"))"#,
        ] {
            assert!(!reaches_tests_run(code, KIT), "{code}");
        }
        let esm = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT","type":"module"}"#),
            (
                "index.mjs",
                br#"import { fork } from "node:child_process"; import { join } from "node:path"; import { fileURLToPath } from "node:url"; fork(join(import.meta.dirname, "x.js")); fork(fileURLToPath(new URL("./y.js", import.meta.url)))"#,
            ),
            ("tests/run.js", b"eval(code)"),
        ]);
        assert!(!esm.meta.test_only_tags.is_empty());
    }

    #[test]
    fn only_the_worker_binding_of_a_worker_threads_destructuring_is_a_worker() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        assert!(!reaches_tests_run(
            r#"const { Worker, BroadcastChannel } = require("worker_threads"); new BroadcastChannel(pick())"#,
            KIT
        ));
        assert!(reaches_tests_run(
            r#"const { BroadcastChannel, Worker: W } = require("worker_threads"); new W(pick())"#,
            KIT
        ));
        assert!(reaches_tests_run(
            r#"const { Worker = Fallback } = require("node:worker_threads"); new Worker(pick())"#,
            KIT
        ));
    }

    #[test]
    fn only_node_module_load_with_a_computed_name_keeps_every_test_file_runtime() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        assert!(!reaches_tests_run(
            "const loader = makeLoader(); loader._load(pick())",
            KIT
        ));
        for code in [
            r#"require("module")._load(pick())"#,
            r#"const Module = require("node:module"); Module._load(pick())"#,
            r#"const { Module } = require("module"); Module._load(pick())"#,
            "module.constructor._load(pick())",
            "const M = module.constructor; M._load(pick())",
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
    }

    /// Whether `lib/boot.test.js` (which calls `eval`) counts as package code
    /// when `entry` holds `code`, across every scan path.
    fn reaches_lib_boot_test(entry: &str, code: &str, manifest: &str) -> bool {
        let analysis = analyze_every_way(&[
            ("package.json", manifest.as_bytes()),
            (entry, code.as_bytes()),
            ("lib/boot.test.js", b"eval(code)"),
        ]);
        analysis.source.eval
    }

    #[test]
    fn a_working_directory_applies_to_the_paths_run_after_it() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        assert!(reaches_lib_boot_test(
            "index.js",
            "module.exports = 1",
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"cd lib && node ./boot.test.js"}}"#
        ));
        for code in [
            r#"require("child_process").execSync("cd lib && node boot.test.js")"#,
            r#"const path = require("path"); require("child_process").fork("boot.test.js", { cwd: path.join(__dirname, "lib") })"#,
            r#"require("child_process").spawn("node", ["./boot.test.js"], { cwd: "lib" })"#,
            r#"process.chdir("lib"); require("child_process").fork("./boot.test.js")"#,
        ] {
            assert!(reaches_lib_boot_test("index.js", code, KIT), "{code}");
        }
    }

    #[test]
    fn a_script_path_built_from_the_module_url_reaches_a_test_file() {
        const KIT: &str = r#"{"name":"kit","license":"MIT","type":"module"}"#;
        for code in [
            r#"import { fork } from "node:child_process"; import path from "node:path"; fork(path.join(import.meta.dirname, "boot.test.js"))"#,
            r#"import { fork } from "node:child_process"; import path from "node:path"; fork(path.resolve(import.meta.dirname, "./boot.test.js"))"#,
            r#"import { fork } from "node:child_process"; import path from "node:path"; import { fileURLToPath } from "node:url"; fork(path.join(path.dirname(fileURLToPath(import.meta.url)), "boot.test.js"))"#,
            r#"import { fork } from "node:child_process"; fork(new URL("./boot.test.js", import.meta.url))"#,
            r#"import { fork } from "node:child_process"; import path from "node:path"; fork(path.join(import.meta.filename, "..", "boot.test.js"))"#,
        ] {
            assert!(reaches_lib_boot_test("lib/index.mjs", code, KIT), "{code}");
        }
        assert!(reaches_lib_boot_test(
            "lib/index.js",
            r#"const path = require("path"); require("child_process").fork(path.join(__filename, "..", "boot.test.js"))"#,
            r#"{"name":"kit","license":"MIT"}"#
        ));
    }

    #[test]
    fn scripts_an_install_script_runs_by_name_bring_their_hooks_and_interpreters() {
        for manifest in [
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"npm run build","build":"tsc","prebuild":"node tests/run.js"}}"#,
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"npm run build","build":"tsc","postbuild":"node tests/run.js"}}"#,
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"npm run build","build":"bash ./setup.sh"}}"#,
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"npm test","test":"node tests/run.js"}}"#,
            r#"{"name":"kit","license":"MIT","scripts":{"install":"npm start","start":"node tests/run.js"}}"#,
        ] {
            assert!(
                reaches_tests_run("module.exports = 1", manifest),
                "{manifest}"
            );
        }
    }

    #[test]
    fn manifest_scripts_and_fields_reach_a_test_file_as_a_shell_and_node_would() {
        for manifest in [
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"cd tests && node run.js"}}"#,
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"npm run setup","setup":"node tests/run.js"}}"#,
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"node tests/./run.js"}}"#,
            r#"{"name":"kit","license":"MIT","scripts":{"postinstall":"node Tests/run.js"}}"#,
            r#"{"name":"kit","license":"MIT","main":"./tests/./run.js"}"#,
            r#"{"name":"kit","license":"MIT","main":"./tests"}"#,
        ] {
            assert!(
                reaches_tests_run("module.exports = 1", manifest),
                "{manifest}"
            );
        }
    }

    #[test]
    fn working_directories_and_names_with_spaces_reach_a_test_file() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"require("child_process").fork("run.js", { cwd: "tests" })"#,
            r#"const path = require("path"); require("child_process").spawn("node", ["run.js"], { cwd: path.join(__dirname, "tests") })"#,
            r#"process.chdir("tests")"#,
            r#"require("child_process").execSync("pushd tests && node run.js")"#,
            r#"require("child_process").execSync("CD tests && node run.js")"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
        for (code, path) in [
            (
                r#"require("child_process").fork("tests/my run.js")"#,
                "tests/my run.js",
            ),
            (
                r#"require("child_process").fork("tests/(x)/run.js")"#,
                "tests/(x)/run.js",
            ),
            (
                r#"require("child_process").execSync("node lib/a,b.test.js")"#,
                "lib/a,b.test.js",
            ),
        ] {
            let analysis = analyze_every_way(&[
                ("package.json", KIT.as_bytes()),
                ("index.js", code.as_bytes()),
                (path, b"eval(code)"),
            ]);
            assert!(analysis.source.eval, "{code}");
        }
    }

    #[test]
    fn a_script_path_built_from_constants_and_the_module_location_is_not_computed() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for code in [
            r#"const { Worker } = require("worker_threads"); new Worker(__filename)"#,
            r#"new Worker(new URL("./worker.js", import.meta.url))"#,
            r#"require("child_process").fork(require.resolve("./worker"))"#,
            r#"const path = require("path"); require("child_process").fork(path.join(__dirname, "worker.js"))"#,
            r#"const { Worker: W } = require("worker_threads"); new W(`${__dirname}/worker.js`)"#,
        ] {
            assert!(!reaches_tests_run(code, KIT), "{code}");
        }
        for code in [
            r#"const { Worker: W } = require("worker_threads"); new W(name)"#,
            r#"require.call(null, pick())"#,
            r#"require.apply(null, [pick()])"#,
            r#"require("module")._load(pick())"#,
        ] {
            assert!(reaches_tests_run(code, KIT), "{code}");
        }
    }

    #[test]
    fn a_reached_test_file_runs_a_sibling_through_its_own_directory() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", br#"require("./tests/a.js")"#),
            (
                "tests/a.js",
                br#"require("child_process").execSync("node " + __dirname + "/b.js")"#,
            ),
            ("tests/b.js", b"eval(code)"),
        ]);
        assert!(analysis.source.eval);
    }

    #[test]
    fn a_manifest_entry_in_a_test_file_the_budget_left_unread_keeps_every_test_file_runtime() {
        let mut analyzer = PackageAnalyzer::with_limits(ScanLimits {
            test_files: 1,
            ..ScanLimits::INSTALL
        });
        analyzer.feed(Path::new("tests/other.js"), b"eval(code)");
        analyzer.feed(Path::new("tests/main.js"), br#"require("./other.js")"#);
        let analysis = analyzer.finish(Some(
            br#"{"name":"kit","license":"MIT","main":"tests/main.js"}"#,
        ));

        assert!(analysis.source.eval);
    }

    #[test]
    fn literals_that_cannot_name_a_test_file_leave_tests_only_tags_alone() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        let urls = (0..1100)
            .map(|index| format!(r#""https://html.spec.whatwg.org/{index}""#))
            .collect::<Vec<_>>()
            .join(",");
        for code in [
            format!("module.exports = [{urls}]"),
            r#"require("./lib")"#.to_owned(),
            r#"console.log("run the test suite with npm test")"#.to_owned(),
        ] {
            assert!(!reaches_tests_run(&code, KIT), "{code}");
        }
    }

    #[test]
    fn a_path_literal_too_long_to_keep_keeps_every_test_file_runtime() {
        let code = format!(
            r#"require("child_process").execSync("node tests/run.js{}")"#,
            " ".repeat(20_000)
        );
        assert!(reaches_tests_run(
            &code,
            r#"{"name":"kit","license":"MIT"}"#
        ));
    }

    #[test]
    fn a_test_file_the_test_budget_left_unread_passes_reachability_on_conservatively() {
        let mut analyzer = PackageAnalyzer::with_limits(ScanLimits {
            test_files: 1,
            ..ScanLimits::INSTALL
        });
        analyzer.feed(Path::new("index.js"), br#"require("./test/z.js")"#);
        analyzer.feed(Path::new("test/a.js"), b"eval(code)");
        analyzer.feed(Path::new("test/z.js"), br#"require("./a.js")"#);
        let analysis = analyzer.finish(Some(br#"{"name":"kit","license":"MIT"}"#));

        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn many_test_files_past_the_test_limit_leave_unreached_tests_tests_only_in_every_walk() {
        let mut files: Vec<(String, Vec<u8>)> = vec![
            (
                "package.json".into(),
                br#"{"name":"kit","license":"MIT"}"#.to_vec(),
            ),
            ("index.js".into(), b"module.exports = 1".to_vec()),
            ("test/000.js".into(), b"eval(code)".to_vec()),
        ];
        files.extend((1..=MAX_FILES_PER_PACKAGE / 4 + 1).map(|index| {
            (
                format!("test/{index:04}.js"),
                b"module.exports = 1".to_vec(),
            )
        }));
        // Past the test limit the streaming feed reads test files in archive
        // order, so only the two directory walks read the same ones.
        let package = tempfile::tempdir().unwrap();
        for (path, content) in &files {
            let file_path = package.path().join(path);
            fs::create_dir_all(file_path.parent().unwrap()).unwrap();
            fs::write(&file_path, content).unwrap();
        }
        let directory =
            cap_std::fs::Dir::open_ambient_dir(package.path(), cap_std::ambient_authority())
                .unwrap();
        for analysis in [
            analyze_package(package.path()),
            analyze_package_from_open_dir(&directory, PackageDirectory::Published),
        ] {
            assert!(!analysis.source.eval);
            assert_eq!(analysis.meta.test_only_tags, ["eval"]);
        }
    }

    #[test]
    fn package_code_past_the_file_limit_keeps_every_test_file_runtime_in_every_walk() {
        let mut files: Vec<(String, Vec<u8>)> = vec![
            (
                "package.json".into(),
                br#"{"name":"kit","license":"MIT"}"#.to_vec(),
            ),
            ("test/run.js".into(), b"eval(code)".to_vec()),
        ];
        files.extend(
            (0..=MAX_FILES_PER_PACKAGE)
                .map(|index| (format!("lib/{index:04}.js"), b"module.exports = 1".to_vec())),
        );
        let files: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(path, content)| (path.as_str(), content.as_slice()))
            .collect();
        let analysis = analyze_every_way(&files);

        assert!(analysis.source.eval);
        assert!(analysis.meta.test_only_tags.is_empty());
    }

    #[test]
    fn test_files_only_tests_reach_stay_tests_only() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT","main":"index.js"}"#),
            (
                "index.js",
                br#"if (process.env.NODE_ENV === "test") console.log("see test/README and ./tests/missing.js"); module.exports = 1"#,
            ),
            ("test/index.js", b"require('./helper')"),
            ("test/helper.js", b"eval(code)"),
        ]);

        assert!(!analysis.source.eval);
        assert_eq!(analysis.meta.test_only_tags, ["eval"]);
    }

    #[test]
    fn javascript_files_written_with_jsx_parse_as_jsx() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"widgets","license":"MIT"}"#),
            (
                "index.js",
                br#"import Widget from "./Widget"; export const App = () => <Widget onClick={() => eval(code)} />;"#,
            ),
            ("plain.js", b"module.exports = a < b ? c : d;"),
        ]);

        assert_eq!(analysis.meta.unparsed_files, 0);
        assert!(analysis.source.eval);
        assert_eq!(analysis.meta.eval_calls, 1);
    }

    #[test]
    fn jsx_whose_closing_tags_are_spaced_out_parses_as_jsx() {
        for source in [
            "export const App = () => <Widget onClick={() => eval(code)} / >;",
            "export const App = () => <div>{eval(code)}< /div>;",
        ] {
            let analysis = analyze_every_way(&[
                ("package.json", br#"{"name":"widgets","license":"MIT"}"#),
                ("index.js", source.as_bytes()),
            ]);
            assert_eq!(analysis.meta.unparsed_files, 0, "{source}");
            assert_eq!(analysis.meta.eval_calls, 1, "{source}");
        }
    }

    #[test]
    fn a_rejected_jsx_parse_leaves_the_first_parse_s_comments_masked() {
        // As JSX, the quote inside the tag opens a string that swallows the comment;
        // the JSX parse fails, and the first parse's reading, with the comment
        // masked as code, must be the one kept.
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", br#"const s = <a>'</a>; /* eval(code) */ '; )"#),
        ]);

        assert_eq!(analysis.meta.unparsed_files, 1);
        assert!(analysis.source.eval);
    }

    #[test]
    fn javascript_that_fails_with_and_without_jsx_stays_unparsed() {
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"broken","license":"MIT"}"#),
            ("index.js", b"const value = ; eval(code)"),
        ]);

        assert_eq!(analysis.meta.unparsed_files, 1);
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

    #[test]
    fn a_directory_required_through_its_own_manifest_reaches_what_it_names() {
        let reached = |files: &[(&str, &[u8])]| analyze_every_way(files).source.eval;
        assert!(reached(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", br#"require("./lib")"#),
            ("lib/package.json", br#"{"main":"../tests/run.js"}"#),
            ("tests/run.js", b"eval(code)"),
        ]));
        assert!(reached(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", br#"require("./lib")"#),
            (
                "lib/package.json",
                br##"{"imports":{"#run":"../tests/run.js"}}"##
            ),
            ("lib/index.js", br##"require("#run")"##),
            ("tests/run.js", b"eval(code)"),
        ]));
        // A fixture's manifest names what it does once the fixture is reached.
        assert!(reached(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", br#"require("./tests/fixtures/pkg")"#),
            (
                "tests/fixtures/pkg/package.json",
                br#"{"main":"../../run.js"}"#
            ),
            ("tests/run.js", b"eval(code)"),
        ]));
        // A fixture's manifest names its own files only when the fixture is reached.
        assert!(!reached(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", b"module.exports = 1"),
            ("tests/fixtures/pkg/package.json", br#"{"main":"index.js"}"#),
            ("tests/fixtures/pkg/index.js", b"eval(code)"),
        ]));
    }

    #[test]
    fn a_directory_manifest_is_read_as_node_reads_it_with_a_bom_in_any_case_or_nested_deep() {
        let mut with_bom = b"\xEF\xBB\xBF".to_vec();
        with_bom.extend_from_slice(br#"{"main":"../tests/run.js"}"#);
        let nested_deep = format!(
            r#"{{"main":"../tests/run.js","x":{}0{}}}"#,
            "[".repeat(200),
            "]".repeat(200)
        );
        for (name, manifest) in [
            ("lib/package.json", with_bom.as_slice()),
            (
                "lib/PACKAGE.JSON",
                br#"{"main":"../tests/run.js"}"#.as_slice(),
            ),
            ("lib/package.json", nested_deep.as_bytes()),
        ] {
            let analysis = analyze_every_way(&[
                ("package.json", br#"{"name":"kit","license":"MIT"}"#),
                ("index.js", br#"require("./lib")"#),
                (name, manifest),
                ("tests/run.js", b"eval(code)"),
            ]);
            assert!(analysis.source.eval, "{name}");
        }
    }

    #[test]
    fn a_directory_manifest_serde_rejects_but_node_reads_counts_as_unknown() {
        for manifest in [
            r#"{"main":"../tests/run.js","x":1e999}"#,
            r#"{"main":"../tests/run.js","x":"\ud800"}"#,
        ] {
            assert!(
                eval_counts_as_package_code(&[
                    ("package.json", r#"{"name":"kit","license":"MIT"}"#),
                    ("index.js", r#"require("./lib")"#),
                    ("lib/package.json", manifest),
                    ("tests/run.js", "eval(code)"),
                ]),
                "{manifest}"
            );
        }
        // A broken fixture nothing reaches changes nothing.
        assert!(!eval_counts_as_package_code(&[
            ("package.json", r#"{"name":"kit","license":"MIT"}"#),
            ("index.js", "module.exports = 1"),
            ("tests/fixtures/broken/package.json", "{ not json"),
            ("tests/run.js", "eval(code)"),
        ]));
    }

    #[test]
    fn a_directory_manifest_s_subpath_patterns_and_name_reach_what_they_map_to() {
        const KIT: &str = r#"{"name":"kit","license":"MIT"}"#;
        for files in [
            [
                ("package.json", KIT),
                ("index.js", r#"require("./lib")"#),
                (
                    "lib/package.json",
                    r##"{"imports":{"#t/*":"./tests/*.js"}}"##,
                ),
                ("lib/index.js", r##"require("#t/run")"##),
                ("lib/tests/run.js", "eval(code)"),
            ]
            .as_slice(),
            &[
                ("package.json", KIT),
                ("index.js", r#"require("dep/run")"#),
                (
                    "node_modules/dep/package.json",
                    r#"{"name":"dep","exports":{"./*":"./test/*.js"}}"#,
                ),
                ("node_modules/dep/test/run.js", "eval(code)"),
            ],
            // A fixture loading itself by the name its manifest gives it.
            &[
                ("package.json", KIT),
                ("index.js", r#"require("./test/fx/a.js")"#),
                (
                    "test/fx/package.json",
                    r#"{"name":"fx","exports":"./b.js"}"#,
                ),
                ("test/fx/a.js", r#"require("fx")"#),
                ("test/fx/b.js", "eval(code)"),
            ],
        ] {
            assert!(eval_counts_as_package_code(files), "{files:?}");
        }
    }

    #[test]
    fn directory_manifests_share_one_reference_budget() {
        let exports: Vec<String> = (0..10_000)
            .map(|index| format!(r#""./{index}":"./f{index}.js""#))
            .collect();
        let manifest = format!(r#"{{"exports":{{{}}}}}"#, exports.join(","));
        let names: Vec<String> = (0..8)
            .map(|index| format!("lib{index}/package.json"))
            .collect();
        let package = |manifests: usize| {
            let mut files: Vec<(&str, &[u8])> = vec![
                ("package.json", br#"{"name":"kit","license":"MIT"}"#),
                ("index.js", b"module.exports = 1"),
                ("tests/run.js", b"eval(code)"),
            ];
            files.extend(
                names[..manifests]
                    .iter()
                    .map(|name| (name.as_str(), manifest.as_bytes())),
            );
            analyze_every_way(&files)
        };
        // One names fewer files than a manifest may; eight together name more
        // than all of them may, so what they name isn't known.
        assert!(!package(1).source.eval);
        assert!(package(8).source.eval);
    }

    #[test]
    fn every_directory_manifest_counts_toward_the_limit_whether_or_not_it_parses() {
        let names: Vec<String> = (0..=MAX_NESTED_MANIFESTS)
            .map(|index| format!("tests/fixture{index}/package.json"))
            .collect();
        let mut files: Vec<(&str, &[u8])> = vec![
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", b"module.exports = 1"),
            ("tests/run.js", b"eval(code)"),
        ];
        files.extend(
            names
                .iter()
                .map(|name| (name.as_str(), b"not json".as_slice())),
        );
        assert!(analyze_every_way(&files).source.eval);
    }

    #[test]
    fn a_directory_manifest_past_the_size_cap_is_left_out_without_failing_the_fingerprint() {
        let oversized = vec![b' '; lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize + 1];
        let analysis = analyze_every_way(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", b"module.exports = 1"),
            ("lib/package.json", &oversized),
            ("tests/run.js", b"eval(code)"),
        ]);
        assert!(analysis.source.eval);
        assert!(!analysis.meta.input_incomplete);
    }

    #[test]
    fn deep_manifest_paths_stay_linear_beside_directory_manifests() {
        let main = format!("{}x", "a/".repeat(100_000));
        let manifest = format!(r#"{{"name":"kit","license":"MIT","main":"{main}"}}"#);
        let time = |fixture: bool| {
            let package = tempfile::tempdir().unwrap();
            fs::write(package.path().join("package.json"), &manifest).unwrap();
            fs::create_dir_all(package.path().join("test/fixture")).unwrap();
            fs::write(package.path().join("test/run.js"), "eval(code)").unwrap();
            if fixture {
                fs::write(package.path().join("test/fixture/package.json"), "{}").unwrap();
            }
            let started = std::time::Instant::now();
            analyze_package(package.path());
            started.elapsed()
        };
        let without = time(false);
        let with = time(true);
        assert!(
            with < without * 5 + std::time::Duration::from_millis(200),
            "with a fixture manifest {with:?}, without {without:?}"
        );
    }
}
