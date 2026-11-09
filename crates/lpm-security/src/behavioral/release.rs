//! A registry's analysis of one published release, read from its gzipped
//! tarball as a stream: nothing is written to disk and no package code runs.
//!
//! It reads every source file the tarball holds, bundled dependencies and
//! hidden files included, within [`ScanLimits::REGISTRY`], and reports each
//! tag with the files it came from, the tags only tests showed, the eval
//! calls of the files the package runs, and how much of the package it read.
//! JavaScript and TypeScript are parsed; the sources of another ecosystem
//! are read by the linear detectors alone.

use super::{
    PackageAnalysis, PackageAnalyzer, ScanLimits, SourceEvidence, TagFiles, path_to_slash, roles,
};
use crate::quality::{QualityCollector, QualityEcosystem, QualityReport};
use flate2::bufread::GzDecoder;
use lpm_common::LpmError;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read};
use std::ops::ControlFlow;

/// Version of the [`ReleaseSignals`] document. Bump it when a field changes
/// meaning or goes away.
pub const RELEASE_SIGNALS_SCHEMA_VERSION: u32 = 1;

/// Largest gzipped tarball read, as a registry accepts at publish.
const MAX_COMPRESSED_BYTES: u64 = 250 * 1024 * 1024;

/// Archive limits, as a registry enforces them at publish.
const ARCHIVE_LIMITS: lpm_extractor::TarArchiveLimits = lpm_extractor::TarArchiveLimits {
    max_entries: 20_000,
    max_metadata_entries: 20_000,
    max_entry_bytes: 200 * 1024 * 1024,
    max_total_entry_bytes: 1024 * 1024 * 1024,
    max_path_depth: lpm_extractor::DEFAULT_MAX_ARCHIVE_PATH_DEPTH,
    max_path_bytes: lpm_extractor::DEFAULT_MAX_ARCHIVE_PATH_BYTES,
    max_metadata_bytes: lpm_extractor::DEFAULT_MAX_TAR_METADATA_BYTES,
};

/// Largest tar stream decompressed: the entries' payload, and room for
/// their headers, padding and path records. Metadata payloads aren't part of
/// the entry total, so without this a stream of metadata records could
/// inflate far past it.
const MAX_DECOMPRESSED_BYTES: u64 = ARCHIVE_LIMITS.max_total_entry_bytes + 128 * 1024 * 1024;

/// Read size for the compressed input and the decompressed tar stream, so
/// tar headers and small files don't re-enter inflate on every short read.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// The language whose source files a release's analysis reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecosystem {
    Js,
    Swift,
    Rust,
    Python,
}

impl Ecosystem {
    /// The quality checks' ecosystem, for the ecosystems the quality score
    /// covers.
    pub fn quality(self) -> Option<QualityEcosystem> {
        match self {
            Self::Js => Some(QualityEcosystem::Js),
            Self::Swift => Some(QualityEcosystem::Swift),
            Self::Rust | Self::Python => None,
        }
    }

    fn reads(self, path: &str) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path);
        let Some((_, extension)) = name.rsplit_once('.') else {
            return false;
        };
        match self {
            Self::Js => {
                super::SOURCE_EXTENSIONS.contains(&extension)
                    && !name.ends_with(".d.ts")
                    && !name.ends_with(".d.mts")
                    && !name.ends_with(".d.cts")
            }
            Self::Swift => extension == "swift",
            Self::Rust => extension == "rs",
            Self::Python => extension == "py",
        }
    }
}

/// What a release's code does, by the files it ships.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseSignals {
    pub schema_version: u32,
    /// The behavioral rules' version, [`super::SCHEMA_VERSION`].
    pub rules_version: u32,
    /// Every tag, by registry key: set when a file the package runs showed
    /// it, or when only tests did (see `test_only_tags`).
    pub tags: BTreeMap<&'static str, bool>,
    /// Tags only test files showed, sorted.
    pub test_only_tags: Vec<String>,
    /// The files each set tag came from.
    pub tag_files: BTreeMap<String, TagFiles>,
    /// Up to three located examples of each rule, files the package runs
    /// first.
    pub evidence: Vec<SourceEvidence>,
    /// The calls that run code from a string in the files the package runs:
    /// `eval()`, `new Function()`, the `vm` module's script runs, and
    /// indirect `eval`.
    pub eval_calls: usize,
    pub url_domains: Vec<String>,
    pub coverage: ReleaseCoverage,
    /// The quality checks the archive decides, for an ecosystem the quality
    /// score covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<QualityReport>,
}

/// How much of a release the analysis read.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseCoverage {
    /// Source files read, whole or sampled.
    pub source_files: usize,
    pub scanned_bytes: u64,
    /// Read but not completely parsed: sampled files, source that doesn't
    /// parse or nests too deeply to, and every source of an ecosystem other
    /// than `js`.
    pub unparsed_files: usize,
    /// Read only at each end.
    pub sampled_files: usize,
    /// Left unread past a file or byte limit, the package's or the tests'.
    pub skipped_files: usize,
    /// The release has a readable `package.json`.
    pub manifest: bool,
    /// Every source file was read whole and parsed, so never for an
    /// ecosystem other than `js`.
    pub complete: bool,
}

/// Analyze a release from its gzipped tarball, and run the quality checks
/// its archive decides when its ecosystem has them. `swift_manifest` is a
/// Swift release's evaluated manifest (`swift package dump-package`); the
/// checks that read it are pending without it.
///
/// The input is read to its end, every file an npm client unpacks included:
/// each gzip member and every tar entry, past zero blocks that end the
/// archive early, so a file can't sit where one extractor reads and this
/// analysis doesn't.
///
/// # Errors
///
/// Returns an error when the input isn't a gzipped tar archive, a gzip
/// member is corrupt, bytes that aren't a gzip member or zero padding follow
/// one, the input breaks an archive limit, holds an entry path outside the
/// package, or can't be read.
pub fn analyze_release_tarball<R: Read>(
    gzipped: R,
    ecosystem: Ecosystem,
    swift_manifest: Option<&serde_json::Value>,
) -> Result<ReleaseSignals, LpmError> {
    let mut analyzer = PackageAnalyzer::with_limits(ScanLimits::REGISTRY);
    let mut quality = ecosystem.quality().map(QualityCollector::new);
    let mut manifest = None;
    let mut buffer = Vec::new();

    visit_release_files(gzipped, |path, relative, size, mut entry| {
        if roles::is_native_artifact_path(path) {
            analyzer.note_native_artifact(path.to_string());
        }
        let quality_bytes = quality
            .as_mut()
            .and_then(|quality| quality.note_file(path, size));
        if path == "package.json" {
            manifest = (size <= lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                .then(|| read_whole(&mut entry, size))
                .transpose()
                .map_err(LpmError::Io)?;
        } else if size > 0 && ecosystem.reads(path) {
            let limits = ScanLimits::REGISTRY;
            if size > limits.full_file_bytes {
                let sample =
                    read_ends(&mut entry, size, limits.sample_bytes).map_err(LpmError::Io)?;
                analyzer.feed_sample(relative, size, &sample);
            } else {
                buffer.clear();
                entry.read_to_end(&mut buffer).map_err(LpmError::Io)?;
                analyzer.feed(relative, &buffer);
                if let (Some(quality), Some(bytes)) = (quality.as_mut(), quality_bytes) {
                    let end = usize::try_from(bytes)
                        .map_or(buffer.len(), |bytes| bytes.min(buffer.len()));
                    quality.add_content(path, &buffer[..end]);
                }
            }
        } else if let (Some(quality), Some(bytes)) = (quality.as_mut(), quality_bytes) {
            buffer.clear();
            entry
                .take(bytes)
                .read_to_end(&mut buffer)
                .map_err(LpmError::Io)?;
            quality.add_content(path, &buffer);
        }
        Ok(())
    })?;

    let quality = quality.map(|quality| quality.finish(manifest.as_deref(), swift_manifest));
    Ok(release_signals(
        analyzer.finish(manifest.as_deref()),
        quality,
    ))
}

/// Runs only the quality checks a release's archive decides, reading its
/// gzipped tarball as [`analyze_release_tarball`] does, for `lpm publish`.
///
/// # Errors
///
/// As [`analyze_release_tarball`]'s.
pub fn analyze_release_quality<R: Read>(
    gzipped: R,
    ecosystem: QualityEcosystem,
    swift_manifest: Option<&serde_json::Value>,
) -> Result<QualityReport, LpmError> {
    let mut quality = QualityCollector::new(ecosystem);
    let mut manifest = None;
    let mut buffer = Vec::new();
    visit_release_files(gzipped, |path, _, size, mut entry| {
        let wanted = quality.note_file(path, size);
        if path == "package.json" {
            manifest = (size <= lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                .then(|| read_whole(&mut entry, size))
                .transpose()
                .map_err(LpmError::Io)?;
        } else if let Some(bytes) = wanted {
            buffer.clear();
            entry
                .take(bytes)
                .read_to_end(&mut buffer)
                .map_err(LpmError::Io)?;
            quality.add_content(path, &buffer);
        }
        Ok(())
    })?;
    Ok(quality.finish(manifest.as_deref(), swift_manifest))
}

/// Calls `visit` with each regular file of a release's gzipped tarball: its
/// package-relative path, as a string and a path, its size and its content.
fn visit_release_files<R: Read>(
    gzipped: R,
    mut visit: impl FnMut(&str, &std::path::Path, u64, &mut dyn Read) -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    let compressed = BufReader::with_capacity(
        READ_BUFFER_BYTES,
        LimitedReader::new(gzipped, MAX_COMPRESSED_BYTES, "compressed"),
    );
    let tar = BufReader::with_capacity(
        READ_BUFFER_BYTES,
        LimitedReader::new(
            GzipMembers::new(compressed),
            MAX_DECOMPRESSED_BYTES,
            "decompressed",
        ),
    );
    lpm_extractor::visit_tar_archive_to_end(tar, ARCHIVE_LIMITS, |mut entry| {
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() && entry_type != tar::EntryType::Continuous {
            return Ok(ControlFlow::Continue(()));
        }
        let Some(relative) = lpm_extractor::package_relative_entry_path(entry.path())? else {
            return Ok(ControlFlow::Continue(()));
        };
        let path = path_to_slash(&relative);
        let size = entry.size();
        visit(&path, &relative, size, &mut entry)?;
        Ok(ControlFlow::<()>::Continue(()))
    })?;
    Ok(())
}

fn read_whole(reader: &mut impl Read, size: u64) -> io::Result<Vec<u8>> {
    let mut content = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
    reader.read_to_end(&mut content)?;
    Ok(content)
}

/// The first and last `sample_bytes` of an entry of `size` bytes, joined by
/// a line break, or the whole entry when the two would meet, as
/// [`PackageAnalyzer::feed`] samples a buffered file.
fn read_ends(reader: &mut impl Read, size: u64, sample_bytes: usize) -> io::Result<Vec<u8>> {
    let chunk = (sample_bytes as u64).min(size);
    let tail_start = size.saturating_sub(chunk);
    if tail_start <= chunk {
        return read_whole(reader, size);
    }
    let mut sample = Vec::with_capacity(sample_bytes.saturating_mul(2).saturating_add(1));
    reader.by_ref().take(chunk).read_to_end(&mut sample)?;
    io::copy(
        &mut reader.by_ref().take(tail_start - chunk),
        &mut io::sink(),
    )?;
    sample.push(b'\n');
    reader.by_ref().take(chunk).read_to_end(&mut sample)?;
    Ok(sample)
}

fn release_signals(analysis: PackageAnalysis, quality: Option<QualityReport>) -> ReleaseSignals {
    let meta = analysis.meta;
    let source = analysis.source;
    let supply = analysis.supply_chain;
    let manifest = analysis.manifest;
    let mut tags = BTreeMap::from([
        ("filesystem", source.filesystem),
        ("network", source.network),
        ("childProcess", source.child_process),
        ("environmentVars", source.environment_vars),
        ("eval", source.eval),
        ("nativeBindings", source.native_bindings),
        ("crypto", source.crypto),
        ("shell", source.shell),
        ("webSocket", source.web_socket),
        ("dynamicRequire", source.dynamic_require),
        ("obfuscated", supply.obfuscated),
        ("possibleObfuscation", supply.possible_obfuscation),
        ("highEntropyStrings", supply.high_entropy_strings),
        ("minified", supply.minified),
        ("telemetry", supply.telemetry),
        ("urlStrings", supply.url_strings),
        ("trivial", supply.trivial),
        ("protestware", supply.protestware),
        ("credentialExfiltration", supply.credential_exfiltration),
        ("encryptedExecution", supply.encrypted_execution),
        ("downloadedExecution", supply.downloaded_execution),
        ("destructiveFilesystem", supply.destructive_filesystem),
        ("gitDependency", manifest.git_dependency),
        ("httpDependency", manifest.http_dependency),
        ("wildcardDependency", manifest.wildcard_dependency),
        ("copyleftLicense", manifest.copyleft_license),
        ("noLicense", manifest.no_license),
        ("customLicense", manifest.custom_license),
    ]);
    for key in &meta.test_only_tags {
        if let Some(value) = tags.get_mut(key.as_str()) {
            *value = true;
        }
    }
    let coverage = ReleaseCoverage {
        source_files: meta.files_scanned + meta.sampled_files,
        scanned_bytes: meta.bytes_scanned,
        unparsed_files: meta.unparsed_files,
        sampled_files: meta.sampled_files,
        skipped_files: meta.skipped_files,
        manifest: !meta.input_incomplete,
        complete: meta.unparsed_files == 0
            && meta.sampled_files == 0
            && meta.skipped_files == 0
            && !meta.limit_reached,
    };
    ReleaseSignals {
        schema_version: RELEASE_SIGNALS_SCHEMA_VERSION,
        rules_version: analysis.version,
        tags,
        test_only_tags: meta.test_only_tags,
        tag_files: meta.tag_files,
        evidence: meta.evidence,
        eval_calls: meta.eval_calls,
        url_domains: meta.url_domains,
        coverage,
        quality,
    }
}

/// The members of a gzip stream, decoded one after another. Zero bytes after
/// a member are padding; any other byte starts another member, as gunzip
/// and Node's zlib read them, so data can't follow the first member unread.
struct GzipMembers<B> {
    decoder: Option<GzDecoder<B>>,
}

impl<B: BufRead> GzipMembers<B> {
    fn new(input: B) -> Self {
        Self {
            decoder: Some(GzDecoder::new(input)),
        }
    }
}

impl<B: BufRead> Read for GzipMembers<B> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while let Some(decoder) = self.decoder.as_mut() {
            let read = decoder.read(buffer)?;
            if read > 0 {
                return Ok(read);
            }
            if let Some(finished) = self.decoder.take() {
                let mut input = finished.into_inner();
                if skip_zero_padding(&mut input)? {
                    self.decoder = Some(GzDecoder::new(input));
                }
            }
        }
        Ok(0)
    }
}

/// Consumes the zero bytes at the front of `input`, and says whether any
/// other byte follows them.
fn skip_zero_padding(input: &mut impl BufRead) -> io::Result<bool> {
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(false);
        }
        let zeros = available.iter().take_while(|&&byte| byte == 0).count();
        let more = zeros < available.len();
        input.consume(zeros);
        if more {
            return Ok(true);
        }
    }
}

/// A reader that fails on reading past `limit` bytes, naming which `stream`
/// was too large.
struct LimitedReader<R> {
    inner: R,
    remaining: u64,
    limit: u64,
    stream: &'static str,
}

impl<R> LimitedReader<R> {
    fn new(inner: R, limit: u64, stream: &'static str) -> Self {
        Self {
            inner,
            remaining: limit,
            limit,
            stream,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return match self.inner.read(&mut [0u8; 1])? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the tarball's {} size is over the {}-byte limit",
                        self.stream, self.limit
                    ),
                )),
            };
        }
        let window = usize::try_from(self.remaining)
            .map_or(buffer.len(), |remaining| remaining.min(buffer.len()));
        let read = self.inner.read(&mut buffer[..window])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        gzip(&tar_archive(entries, tar::EntryType::Regular))
    }

    fn tar_archive(entries: &[(&str, &[u8])], entry_type: tar::EntryType) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(entry_type);
            builder
                .append_data(&mut header, format!("package/{path}"), *content)
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        io::Write::write_all(&mut encoder, bytes).unwrap();
        encoder.finish().unwrap()
    }

    const PAYLOAD: &[u8] = br#"require("child_process").exec(process.argv[2])"#;

    fn first_part() -> Vec<u8> {
        let archive = tar_archive(
            &[("package.json", br#"{"name":"kit","license":"MIT"}"#)],
            tar::EntryType::Regular,
        );
        archive[..archive.len() - 1024].to_vec()
    }

    fn analyze(entries: &[(&str, &[u8])]) -> ReleaseSignals {
        analyze_release_tarball(tarball(entries).as_slice(), Ecosystem::Js, None).unwrap()
    }

    #[test]
    fn reports_every_tag_the_files_each_came_from_and_the_tags_only_tests_showed() {
        let index = b"module.exports = input => eval(input)";
        let test = br#"require("child_process").spawn("node")"#;
        let signals = analyze(&[
            (
                "package.json",
                br#"{"name":"kit","license":"MIT","main":"lib/index.js"}"#,
            ),
            ("lib/index.js", index),
            ("test/run.test.js", test),
            ("lib/types.d.ts", b"export declare function run(): void"),
            ("lib/empty.js", b""),
        ]);

        assert_eq!(signals.schema_version, RELEASE_SIGNALS_SCHEMA_VERSION);
        assert_eq!(signals.tags.len(), 28);
        assert!(signals.tags["eval"]);
        assert!(signals.tags["childProcess"]);
        assert!(!signals.tags["network"]);
        assert!(!signals.tags["noLicense"]);
        assert_eq!(signals.test_only_tags, ["childProcess"]);
        assert_eq!(
            signals.tag_files["childProcess"],
            TagFiles {
                files: vec!["test/run.test.js".to_owned()],
                file_count: 1,
                tests_only: true,
            }
        );
        assert_eq!(signals.tag_files["eval"].files, ["lib/index.js"]);
        assert_eq!(signals.eval_calls, 1);
        assert_eq!(
            signals.coverage,
            ReleaseCoverage {
                source_files: 2,
                scanned_bytes: (index.len() + test.len()) as u64,
                unparsed_files: 0,
                sampled_files: 0,
                skipped_files: 0,
                manifest: true,
                complete: true,
            }
        );
    }

    #[test]
    fn reads_bundled_dependencies_native_addons_and_hidden_files() {
        let signals = analyze(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            (
                "node_modules/helper/index.js",
                br#"require("child_process").spawn("sh")"#,
            ),
            (".hidden/loader.js", b"eval(payload)"),
            ("prebuilds/darwin-arm64/addon.node", b"\x7fELF"),
        ]);

        assert!(signals.tags["childProcess"]);
        assert!(signals.tags["eval"]);
        assert!(signals.tags["nativeBindings"]);
        assert_eq!(
            signals.tag_files["nativeBindings"].files,
            ["prebuilds/darwin-arm64/addon.node"]
        );
        assert!(signals.test_only_tags.is_empty());
    }

    #[test]
    fn samples_both_ends_of_a_source_file_too_large_to_read_whole() {
        let limits = ScanLimits::REGISTRY;
        let mut bundle = vec![b' '; usize::try_from(limits.full_file_bytes).unwrap() + 1];
        let tail = b"eval(payload)";
        let start = bundle.len() - tail.len();
        bundle[start..].copy_from_slice(tail);

        let signals = analyze(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("dist/bundle.js", &bundle),
        ]);

        assert!(signals.tags["eval"]);
        assert_eq!(signals.coverage.sampled_files, 1);
        assert_eq!(signals.coverage.source_files, 1);
        assert_eq!(
            signals.coverage.scanned_bytes,
            limits.sample_bytes as u64 * 2 + 1
        );
        assert!(!signals.coverage.complete);
    }

    #[test]
    fn reads_the_sources_of_the_release_ecosystem() {
        let entries: &[(&str, &[u8])] = &[
            ("Package.swift", b"// swift-tools-version:5.9\nlet x = 1"),
            (
                "Sources/Kit/Kit.swift",
                b"let url = \"https://example.com\"",
            ),
            ("scripts/build.js", b"eval(code)"),
        ];
        let signals =
            analyze_release_tarball(tarball(entries).as_slice(), Ecosystem::Swift, None).unwrap();

        assert!(!signals.tags["eval"]);
        assert_eq!(signals.coverage.source_files, 2);
        assert!(!signals.coverage.manifest);
    }

    #[test]
    fn reads_another_ecosystem_s_sources_without_the_javascript_parser() {
        let entries: &[(&str, &[u8])] = &[
            ("pkg/run.py", br#"print("eval(x)")"#),
            ("pkg/kit.py", b"def run():\n    return 1\n"),
        ];
        let signals =
            analyze_release_tarball(tarball(entries).as_slice(), Ecosystem::Python, None).unwrap();

        assert!(signals.tags["eval"]);
        assert_eq!(signals.coverage.source_files, 2);
        assert_eq!(signals.coverage.unparsed_files, 2);
        assert!(!signals.coverage.complete);
    }

    #[test]
    fn reads_a_release_nested_too_deeply_to_parse_without_failing() {
        let nested = format!("x={}eval(y){};", "[".repeat(100_000), "]".repeat(100_000));
        let signals = analyze(&[
            ("package.json", br#"{"name":"kit","license":"MIT"}"#),
            ("index.js", nested.as_bytes()),
        ]);

        assert!(signals.tags["eval"]);
        assert_eq!(signals.coverage.unparsed_files, 1);
        assert!(!signals.coverage.complete);
    }

    #[test]
    fn refuses_input_that_is_not_a_gzipped_tarball() {
        assert!(analyze_release_tarball(b"not a tarball".as_slice(), Ecosystem::Js, None).is_err());
        let mut truncated = tarball(&[("index.js", b"module.exports = 1")]);
        truncated.truncate(truncated.len() / 2);
        assert!(analyze_release_tarball(truncated.as_slice(), Ecosystem::Js, None).is_err());
    }

    #[test]
    fn refuses_an_entry_outside_the_package() {
        let mut raw = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let content = b"eval(x)";
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_gnu_mut().unwrap().name[..23].copy_from_slice(b"package/../../escape.js");
        header.set_cksum();
        raw.append(&header, content.as_slice()).unwrap();
        let mut gzipped = GzEncoder::new(Vec::new(), Compression::fast());
        io::Write::write_all(&mut gzipped, &raw.into_inner().unwrap()).unwrap();

        let error =
            analyze_release_tarball(gzipped.finish().unwrap().as_slice(), Ecosystem::Js, None)
                .unwrap_err();
        assert!(error.to_string().contains("path traversal"), "{error}");
    }

    #[test]
    fn reads_the_files_of_every_gzip_member() {
        let mut input = gzip(&first_part());
        input.extend(gzip(&tar_archive(
            &[("lib/run.js", PAYLOAD)],
            tar::EntryType::Regular,
        )));
        input.extend_from_slice(&[0; 64]);

        let signals = analyze_release_tarball(input.as_slice(), Ecosystem::Js, None).unwrap();

        assert!(signals.tags["childProcess"]);
        assert_eq!(signals.tag_files["childProcess"].files, ["lib/run.js"]);
    }

    #[test]
    fn reads_the_entries_after_a_zero_block_inside_the_archive() {
        let mut archive = first_part();
        archive.extend_from_slice(&[0; 512]);
        archive.extend(tar_archive(
            &[("lib/run.js", PAYLOAD)],
            tar::EntryType::Regular,
        ));

        let signals =
            analyze_release_tarball(gzip(&archive).as_slice(), Ecosystem::Js, None).unwrap();

        assert!(signals.tags["childProcess"]);
    }

    #[test]
    fn refuses_input_after_a_gzip_member_that_is_not_another_member() {
        for trailing in [b"trailing bytes".as_slice(), b"\x00\x00trailing bytes"] {
            let mut input = tarball(&[("index.js", b"module.exports = 1")]);
            input.extend_from_slice(trailing);
            assert!(analyze_release_tarball(input.as_slice(), Ecosystem::Js, None).is_err());
        }

        let mut corrupt = tarball(&[("index.js", b"module.exports = 1")]);
        let crc = corrupt.len() - 8;
        corrupt[crc] ^= 0xff;
        assert!(analyze_release_tarball(corrupt.as_slice(), Ecosystem::Js, None).is_err());
    }

    #[test]
    fn reads_contiguous_files_git_paths_and_windows_device_names_as_npm_unpacks_them() {
        for (path, entry_type) in [
            ("lib/run.js", tar::EntryType::Continuous),
            (".git/run.js", tar::EntryType::Regular),
            ("lib/aux.js", tar::EntryType::Regular),
        ] {
            let archive = tar_archive(&[(path, PAYLOAD)], entry_type);
            let signals =
                analyze_release_tarball(gzip(&archive).as_slice(), Ecosystem::Js, None).unwrap();
            assert!(signals.tags["childProcess"], "{path}");
            assert_eq!(signals.coverage.source_files, 1, "{path}");
        }
    }

    #[test]
    fn reports_the_archive_quality_checks_of_a_scored_ecosystem() {
        let entries: &[(&str, &[u8])] = &[
            (
                "package.json",
                br#"{"name":"@lpm.dev/acme.kit","version":"1.0.0","license":"MIT","sideEffects":false}"#,
            ),
            ("index.js", b"module.exports = 1"),
            ("LICENSE", b"MIT"),
        ];
        let signals = analyze(entries);
        let quality = signals.quality.expect("JavaScript is scored");
        assert_eq!(quality.ecosystem, QualityEcosystem::Js);
        let check = |id: &str| quality.checks.iter().find(|check| check.id == id).unwrap();
        assert_eq!(check("license").points, 5);
        assert_eq!(check("license-file").points, 2);
        assert_eq!(check("side-effects").points, 2);
        assert_eq!(check("readme").points, 0);

        let alone =
            analyze_release_quality(tarball(entries).as_slice(), QualityEcosystem::Js, None)
                .unwrap();
        assert_eq!(
            serde_json::to_value(&alone).unwrap(),
            serde_json::to_value(&quality).unwrap(),
            "lpm publish scores the archive as the registry does"
        );
    }

    #[test]
    fn reports_no_quality_checks_for_an_unscored_ecosystem() {
        let signals = analyze_release_tarball(
            tarball(&[("main.py", b"print(1)")]).as_slice(),
            Ecosystem::Python,
            None,
        )
        .unwrap();
        assert!(signals.quality.is_none());
        assert!(
            serde_json::to_value(&signals)
                .unwrap()
                .get("quality")
                .is_none()
        );
    }

    #[test]
    fn passes_the_evaluated_manifest_to_the_swift_checks() {
        let entries: &[(&str, &[u8])] = &[
            ("Package.swift", b"// swift-tools-version: 6.0"),
            ("Sources/Kit/Kit.swift", b"public struct Kit {}"),
        ];
        let pending = analyze_release_tarball(tarball(entries).as_slice(), Ecosystem::Swift, None)
            .unwrap()
            .quality
            .unwrap();
        let platforms = |report: &QualityReport| {
            report
                .checks
                .iter()
                .find(|check| check.id == "platforms")
                .map(|check| check.status)
                .unwrap()
        };
        assert_eq!(platforms(&pending), crate::quality::CheckStatus::Pending);

        let manifest = serde_json::json!({
            "toolsVersion": { "_version": "6.0.0" },
            "platforms": [{ "platformName": "macos", "version": "14.0" }],
            "products": [], "targets": [], "dependencies": []
        });
        let scored = analyze_release_tarball(
            tarball(entries).as_slice(),
            Ecosystem::Swift,
            Some(&manifest),
        )
        .unwrap()
        .quality
        .unwrap();
        assert_eq!(platforms(&scored), crate::quality::CheckStatus::Passed);
    }

    #[test]
    fn stops_decompressing_past_the_archive_size_limit() {
        let mut reader = LimitedReader::new([0u8; 16].as_slice(), 8, "decompressed");
        let mut sink = Vec::new();
        let error = reader.read_to_end(&mut sink).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("decompressed"), "{error}");

        let mut exact = LimitedReader::new([0u8; 8].as_slice(), 8, "decompressed");
        assert_eq!(exact.read_to_end(&mut sink).unwrap(), 8);
    }

    #[test]
    fn stops_reading_input_past_the_compressed_size_limit() {
        let mut reader = LimitedReader::new([0u8; 16].as_slice(), 8, "compressed");
        let mut sink = Vec::new();
        let error = reader.read_to_end(&mut sink).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
