//! A registry's analysis of one published release, read from its gzipped
//! tarball as a stream: nothing is written to disk and no package code runs.
//!
//! It reads every source file the tarball holds, bundled dependencies and
//! hidden files included, within [`ScanLimits::REGISTRY`], and reports each
//! tag with the files it came from, the tags only tests showed, the eval
//! calls of the files the package runs, and how much of the package it read.

use super::{
    PackageAnalysis, PackageAnalyzer, ScanLimits, SourceEvidence, TagFiles, path_to_slash, roles,
};
use flate2::read::GzDecoder;
use lpm_common::LpmError;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, Read};
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

/// The language whose source files a release's analysis reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecosystem {
    Js,
    Swift,
    Rust,
    Python,
}

impl Ecosystem {
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
    /// The `eval()` and `new Function()` calls of the files the package runs.
    pub eval_calls: usize,
    pub url_domains: Vec<String>,
    pub coverage: ReleaseCoverage,
}

/// How much of a release the analysis read.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseCoverage {
    /// Source files read, whole or sampled.
    pub source_files: usize,
    pub scanned_bytes: u64,
    /// Read but not completely parsed, sampled files included.
    pub unparsed_files: usize,
    /// Read only at each end.
    pub sampled_files: usize,
    /// Left unread past the file or byte limit.
    pub skipped_files: usize,
    /// The release has a readable `package.json`.
    pub manifest: bool,
    /// Every source file was read whole and parsed.
    pub complete: bool,
}

/// Analyze a release from its gzipped tarball.
///
/// # Errors
///
/// Returns an error when the input isn't a gzipped tar archive, breaks an
/// archive limit, holds an entry path outside the package, or can't be read.
pub fn analyze_release_tarball<R: Read>(
    gzipped: R,
    ecosystem: Ecosystem,
) -> Result<ReleaseSignals, LpmError> {
    let compressed = CappedReader {
        inner: gzipped,
        remaining: MAX_COMPRESSED_BYTES,
    };
    let mut analyzer = PackageAnalyzer::with_limits(ScanLimits::REGISTRY);
    let mut manifest = None;
    let mut buffer = Vec::new();

    lpm_extractor::visit_tar_archive(GzDecoder::new(compressed), ARCHIVE_LIMITS, |mut entry| {
        if !entry.header().entry_type().is_file() {
            return Ok(ControlFlow::Continue(()));
        }
        let Some(relative) = lpm_extractor::sanitize_entry_path(entry.path())? else {
            return Ok(ControlFlow::Continue(()));
        };
        let path = path_to_slash(&relative);
        let size = entry.size();
        if roles::is_native_artifact_path(&path) {
            analyzer.note_native_artifact(path.clone());
        }
        if path == "package.json" {
            manifest = (size <= lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
                .then(|| read_whole(&mut entry, size))
                .transpose()
                .map_err(LpmError::Io)?;
        } else if size > 0 && ecosystem.reads(&path) {
            let limits = ScanLimits::REGISTRY;
            if size > limits.full_file_bytes {
                let sample =
                    read_ends(&mut entry, size, limits.sample_bytes).map_err(LpmError::Io)?;
                analyzer.feed_sample(&relative, size, &sample);
            } else {
                buffer.clear();
                entry.read_to_end(&mut buffer).map_err(LpmError::Io)?;
                analyzer.feed(&relative, &buffer);
            }
        }
        Ok(ControlFlow::<()>::Continue(()))
    })?;

    Ok(release_signals(analyzer.finish(manifest.as_deref())))
}

fn read_whole(reader: &mut impl Read, size: u64) -> io::Result<Vec<u8>> {
    let mut content = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
    reader.read_to_end(&mut content)?;
    Ok(content)
}

/// The first and last `sample_bytes` of an entry of `size` bytes, joined by
/// a line break, as [`PackageAnalyzer::feed`] samples a buffered file.
fn read_ends(reader: &mut impl Read, size: u64, sample_bytes: usize) -> io::Result<Vec<u8>> {
    let chunk = (sample_bytes as u64).min(size);
    let mut sample = Vec::with_capacity(sample_bytes.saturating_mul(2).saturating_add(1));
    reader.by_ref().take(chunk).read_to_end(&mut sample)?;
    let tail_start = size.saturating_sub(chunk);
    if tail_start > chunk {
        io::copy(
            &mut reader.by_ref().take(tail_start - chunk),
            &mut io::sink(),
        )?;
        sample.push(b'\n');
        reader.by_ref().take(chunk).read_to_end(&mut sample)?;
    }
    Ok(sample)
}

fn release_signals(analysis: PackageAnalysis) -> ReleaseSignals {
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
    }
}

/// A reader that fails once more than `remaining` bytes have been read, so a
/// tarball larger than a registry accepts isn't decompressed.
struct CappedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.remaining = self.remaining.checked_sub(read as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the tarball is larger than {MAX_COMPRESSED_BYTES} bytes"),
            )
        })?;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    fn tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            builder
                .append_data(&mut header, format!("package/{path}"), *content)
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn analyze(entries: &[(&str, &[u8])]) -> ReleaseSignals {
        analyze_release_tarball(tarball(entries).as_slice(), Ecosystem::Js).unwrap()
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
    fn reads_bundled_dependencies_native_addons_and_the_hidden_files_installs_skip() {
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
            analyze_release_tarball(tarball(entries).as_slice(), Ecosystem::Swift).unwrap();

        assert!(!signals.tags["eval"]);
        assert_eq!(signals.coverage.source_files, 2);
        assert!(!signals.coverage.manifest);
    }

    #[test]
    fn refuses_input_that_is_not_a_gzipped_tarball() {
        assert!(analyze_release_tarball(b"not a tarball".as_slice(), Ecosystem::Js).is_err());
        let mut truncated = tarball(&[("index.js", b"module.exports = 1")]);
        truncated.truncate(truncated.len() / 2);
        assert!(analyze_release_tarball(truncated.as_slice(), Ecosystem::Js).is_err());
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

        let error = analyze_release_tarball(gzipped.finish().unwrap().as_slice(), Ecosystem::Js)
            .unwrap_err();
        assert!(error.to_string().contains("path traversal"), "{error}");
    }

    #[test]
    fn stops_reading_input_past_the_compressed_size_limit() {
        let mut reader = CappedReader {
            inner: [0u8; 16].as_slice(),
            remaining: 8,
        };
        let mut sink = Vec::new();
        let error = reader.read_to_end(&mut sink).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
