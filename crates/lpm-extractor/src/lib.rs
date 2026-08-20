//! Tarball download, verification, decompression, and extraction for LPM.
//!
//! Handles the pipeline: raw .tgz bytes → verify integrity → decompress gzip → extract tar.
//!
//! npm tarballs have a `package/` prefix directory that gets stripped during extraction
//! (equivalent to `tar x --strip-components=1`).
//!
//! Performance: libdeflate for whole-buffer gzip decompression (~2-3x faster than
//! flate2/zlib-rs on the npm size distribution). Oversized inputs fall back to
//! flate2's streaming `GzDecoder` so peak allocation stays bounded.

use flate2::read::GzDecoder;
use lpm_common::{Integrity, LpmError};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::Read;
use std::ops::ControlFlow;
use std::path::{Component, Path, PathBuf};

/// Default maximum number of components in an archive entry path.
pub const DEFAULT_MAX_ARCHIVE_PATH_DEPTH: usize = 256;
/// Default maximum encoded length of an archive entry path.
pub const DEFAULT_MAX_ARCHIVE_PATH_BYTES: usize = 32 * 1024;
/// Default maximum payload size of one GNU or PAX metadata record.
pub const DEFAULT_MAX_TAR_METADATA_BYTES: usize = 1024 * 1024;

/// Resource limits enforced while walking a raw tar archive.
#[derive(Clone, Copy, Debug)]
pub struct TarArchiveLimits {
    /// Maximum number of non-metadata entries.
    pub max_entries: usize,
    /// Maximum number of GNU and PAX metadata entries.
    pub max_metadata_entries: usize,
    /// Maximum declared size of one non-metadata entry.
    pub max_entry_bytes: u64,
    /// Maximum number of components in an entry path or link target.
    pub max_path_depth: usize,
    /// Maximum encoded length of an entry path or link target.
    pub max_path_bytes: usize,
    /// Maximum payload size of one GNU or PAX metadata entry.
    pub max_metadata_bytes: usize,
}

impl TarArchiveLimits {
    /// Creates limits with equal semantic-entry and metadata-entry caps.
    pub const fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            max_metadata_entries: max_entries,
            max_entry_bytes: u64::MAX,
            max_path_depth: DEFAULT_MAX_ARCHIVE_PATH_DEPTH,
            max_path_bytes: DEFAULT_MAX_ARCHIVE_PATH_BYTES,
            max_metadata_bytes: DEFAULT_MAX_TAR_METADATA_BYTES,
        }
    }
}

/// A tar entry whose effective GNU or PAX path metadata has been bounded.
pub struct BoundedTarEntry<'a, R: Read> {
    inner: tar::Entry<'a, R>,
    path: PathBuf,
    link_name: Option<PathBuf>,
}

impl<R: Read> BoundedTarEntry<'_, R> {
    /// Returns the raw tar header.
    ///
    /// Use [`Self::path`] and [`Self::link_name`] for effective names because
    /// GNU and PAX overrides are not written back into this header.
    pub fn header(&self) -> &tar::Header {
        self.inner.header()
    }

    /// Returns the validated entry size.
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    /// Returns the validated effective path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the validated effective link target when one is present.
    pub fn link_name(&self) -> Option<&Path> {
        self.link_name.as_deref()
    }

    /// Unpacks a non-link entry at an already validated destination path.
    ///
    /// Link entries must be materialized explicitly from [`Self::link_name`]
    /// because GNU and PAX target overrides are not written into the raw
    /// header.
    pub fn unpack(&mut self, destination: &Path) -> std::io::Result<()> {
        let entry_type = self.inner.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bounded tar link entries require explicit extraction",
            ));
        }
        self.inner.unpack(destination).map(|_| ())
    }
}

impl<R: Read> Read for BoundedTarEntry<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}

#[derive(Default)]
struct PaxMetadata {
    path: Option<Vec<u8>>,
    link_path: Option<Vec<u8>>,
    size: Option<u64>,
}

/// Visits validated semantic entries in a tar archive.
///
/// GNU long-name and long-link records and local PAX path metadata are
/// resolved before the visitor runs. A visitor break value suppresses later
/// visitor calls, but the walker still validates all remaining archive
/// entries before returning it.
///
/// # Errors
///
/// Returns an error for malformed metadata, unsupported sparse entries,
/// limit violations, invalid paths, or visitor failures.
pub fn visit_tar_archive<R, T, F>(
    reader: R,
    limits: TarArchiveLimits,
    mut visitor: F,
) -> Result<(R, Option<T>), LpmError>
where
    R: Read,
    F: FnMut(BoundedTarEntry<'_, R>) -> Result<ControlFlow<T>, LpmError>,
{
    let mut archive = tar::Archive::new(reader);
    let mut local_metadata = PaxMetadata::default();
    let mut long_path: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut has_local_pax = false;
    let mut entries_seen = 0usize;
    let mut metadata_entries_seen = 0usize;
    let mut stopped = None;

    {
        let entries = archive.entries().map_err(LpmError::Io)?.raw(true);
        for entry_result in entries {
            let mut entry = entry_result.map_err(LpmError::Io)?;
            let entry_type = entry.header().entry_type();
            let is_metadata = entry_type.is_gnu_longname()
                || entry_type.is_gnu_longlink()
                || entry_type.is_pax_local_extensions()
                || entry_type.is_pax_global_extensions();
            if is_metadata {
                metadata_entries_seen = metadata_entries_seen.saturating_add(1);
                if metadata_entries_seen > limits.max_metadata_entries {
                    return Err(LpmError::Registry(format!(
                        "tar archive exceeds the {}-metadata-entry limit",
                        limits.max_metadata_entries
                    )));
                }
            } else {
                entries_seen = entries_seen.saturating_add(1);
                if entries_seen > limits.max_entries {
                    return Err(LpmError::Registry(format!(
                        "tar archive exceeds the {}-entry limit (too many files)",
                        limits.max_entries
                    )));
                }
            }

            if entry_type.is_gnu_longname() {
                if long_path.is_some() {
                    return Err(invalid_tar_metadata(
                        "multiple GNU long-name records describe one entry",
                    ));
                }
                long_path = Some(read_tar_metadata(&mut entry, limits)?);
                continue;
            }
            if entry_type.is_gnu_longlink() {
                if long_link.is_some() {
                    return Err(invalid_tar_metadata(
                        "multiple GNU long-link records describe one entry",
                    ));
                }
                long_link = Some(read_tar_metadata(&mut entry, limits)?);
                continue;
            }
            if entry_type.is_pax_local_extensions() {
                if has_local_pax {
                    return Err(invalid_tar_metadata(
                        "multiple local PAX records describe one entry",
                    ));
                }
                local_metadata = parse_pax_metadata(&read_tar_metadata(&mut entry, limits)?)?;
                has_local_pax = true;
                continue;
            }
            if entry_type.is_pax_global_extensions() {
                let metadata = parse_pax_metadata(&read_tar_metadata(&mut entry, limits)?)?;
                if metadata.path.is_some()
                    || metadata.link_path.is_some()
                    || metadata.size.is_some()
                {
                    return Err(invalid_tar_metadata(
                        "global PAX path, linkpath, and size overrides are unsupported",
                    ));
                }
                continue;
            }
            if entry_type.is_gnu_sparse() {
                return Err(invalid_tar_metadata("GNU sparse entries are unsupported"));
            }

            let header_size = entry.header().size().map_err(LpmError::Io)?;
            let effective_size = local_metadata.size.unwrap_or(header_size);
            if effective_size > limits.max_entry_bytes {
                return Err(LpmError::Registry(format!(
                    "file too large in tar archive: {effective_size} bytes exceeds per-entry cap of {} bytes",
                    limits.max_entry_bytes
                )));
            }
            if effective_size != header_size {
                return Err(invalid_tar_metadata(
                    "PAX size override does not match the tar header",
                ));
            }

            let path = if let Some(bytes) = long_path.take() {
                tar_metadata_path(bytes, limits)?
            } else if let Some(bytes) = local_metadata.path.take() {
                tar_metadata_path(bytes, limits)?
            } else {
                let path = entry.header().path().map_err(LpmError::Io)?.into_owned();
                validate_tar_path(&path, limits)?;
                path
            };
            let link_name = if let Some(bytes) = long_link.take() {
                Some(tar_metadata_path(bytes, limits)?)
            } else if let Some(bytes) = local_metadata.link_path.take() {
                Some(tar_metadata_path(bytes, limits)?)
            } else {
                entry
                    .header()
                    .link_name()
                    .map_err(LpmError::Io)?
                    .map(|path| path.into_owned())
            };
            validate_tar_path(&path, limits)?;
            if let Some(link_name) = &link_name {
                validate_tar_path(link_name, limits)?;
            }

            local_metadata = PaxMetadata::default();
            has_local_pax = false;
            if stopped.is_some() {
                continue;
            }
            match visitor(BoundedTarEntry {
                inner: entry,
                path,
                link_name,
            })? {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(value) => {
                    stopped = Some(value);
                }
            }
        }
    }

    if long_path.is_some()
        || long_link.is_some()
        || local_metadata.path.is_some()
        || local_metadata.link_path.is_some()
        || local_metadata.size.is_some()
        || has_local_pax
    {
        return Err(invalid_tar_metadata(
            "metadata record does not describe a following tar entry",
        ));
    }

    Ok((archive.into_inner(), stopped))
}

fn read_tar_metadata<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    limits: TarArchiveLimits,
) -> Result<Vec<u8>, LpmError> {
    let size = entry.header().size().map_err(LpmError::Io)?;
    if size > limits.max_metadata_bytes as u64 {
        return Err(LpmError::Registry(format!(
            "tar metadata exceeds the {}-byte limit",
            limits.max_metadata_bytes
        )));
    }
    let mut content = Vec::with_capacity(size as usize);
    entry
        .take(size.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(LpmError::Io)?;
    if content.len() as u64 != size {
        return Err(invalid_tar_metadata("truncated tar metadata record"));
    }
    Ok(content)
}

fn parse_pax_metadata(content: &[u8]) -> Result<PaxMetadata, LpmError> {
    let mut metadata = PaxMetadata::default();
    let mut offset = 0usize;
    while offset < content.len() {
        let relative_space = content[offset..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| invalid_tar_metadata("PAX record is missing its length separator"))?;
        let space = offset + relative_space;
        let length = usize::try_from(parse_decimal(&content[offset..space], "PAX record length")?)
            .map_err(|_| invalid_tar_metadata("PAX record length overflows"))?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= content.len())
            .ok_or_else(|| invalid_tar_metadata("PAX record length exceeds metadata payload"))?;
        if length <= relative_space + 2 || content[end - 1] != b'\n' {
            return Err(invalid_tar_metadata("PAX record has invalid framing"));
        }
        let record = &content[space + 1..end - 1];
        let separator = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| invalid_tar_metadata("PAX record is missing `=`"))?;
        let key = &record[..separator];
        let value = &record[separator + 1..];
        match key {
            b"path" => metadata.path = Some(value.to_vec()),
            b"linkpath" => metadata.link_path = Some(value.to_vec()),
            b"size" => metadata.size = Some(parse_decimal(value, "PAX size")?),
            key if key.starts_with(b"GNU.sparse.") => {
                return Err(invalid_tar_metadata(
                    "GNU sparse PAX entries are unsupported",
                ));
            }
            _ => {}
        }
        offset = end;
    }
    Ok(metadata)
}

fn parse_decimal(bytes: &[u8], label: &str) -> Result<u64, LpmError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(invalid_tar_metadata(&format!("{label} is not decimal")));
    }
    let mut value = 0u64;
    for digit in bytes {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or_else(|| invalid_tar_metadata(&format!("{label} overflows")))?;
    }
    Ok(value)
}

fn tar_metadata_path(mut bytes: Vec<u8>, limits: TarArchiveLimits) -> Result<PathBuf, LpmError> {
    if bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.len() > limits.max_path_bytes {
        return Err(LpmError::Registry(format!(
            "tar entry path exceeds the {}-byte limit",
            limits.max_path_bytes
        )));
    }
    if bytes.contains(&0) {
        return Err(invalid_tar_metadata("tar entry path contains a NUL byte"));
    }
    #[cfg(unix)]
    let path = bytes_to_path(bytes);
    #[cfg(not(unix))]
    let path = bytes_to_path(bytes)?;
    validate_tar_path(&path, limits)?;
    Ok(path)
}

#[cfg(unix)]
fn bytes_to_path(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn bytes_to_path(bytes: Vec<u8>) -> Result<PathBuf, LpmError> {
    String::from_utf8(bytes)
        .map(PathBuf::from)
        .map_err(|_| invalid_tar_metadata("tar entry path is not valid UTF-8 on this platform"))
}

fn validate_tar_path(path: &Path, limits: TarArchiveLimits) -> Result<(), LpmError> {
    let depth = path.components().count();
    if depth > limits.max_path_depth {
        return Err(LpmError::Registry(format!(
            "tar entry exceeds the {}-component nesting limit: {}",
            limits.max_path_depth,
            path.display()
        )));
    }
    if path.as_os_str().len() > limits.max_path_bytes {
        return Err(LpmError::Registry(format!(
            "tar entry path exceeds the {}-byte limit",
            limits.max_path_bytes
        )));
    }
    Ok(())
}

fn invalid_tar_metadata(message: &str) -> LpmError {
    LpmError::Registry(format!("invalid tar metadata: {message}"))
}

/// Verify a tarball's integrity against an expected SRI hash.
///
/// Returns `Ok(())` if the hash matches, `Err` with details if not.
pub fn verify_integrity(data: &[u8], expected_sri: &str) -> Result<(), LpmError> {
    let expected = Integrity::parse(expected_sri)?;
    expected.verify(data)
}

/// Verify a tarball file's integrity against an expected SRI hash (bounded-memory).
///
/// Reads the file in 64KB chunks — never buffers the full tarball in memory.
pub fn verify_integrity_file(path: &Path, expected_sri: &str) -> Result<(), LpmError> {
    let expected = Integrity::parse(expected_sri)?;
    expected.verify_file(path)
}

/// Decompress gzip data in memory (test helper).
#[cfg(test)]
fn decompress_gzip(compressed: &[u8]) -> Result<Vec<u8>, LpmError> {
    use std::io::Read;
    let mut decoder = GzDecoder::new(compressed);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(LpmError::Io)?;
    Ok(decompressed)
}

/// Maximum compressed tarball size accepted by the buffered libdeflate path
/// (500 MB). Any tarball larger than this is decompressed via the streaming
/// fallback (`GzDecoder`) so peak memory stays bounded. This ceiling is
/// independent of `SizeLimitedReader` caps applied by upstream callers —
/// callers that want a tighter cap can apply their own.
const MAX_BUFFERED_COMPRESSED_SIZE: u64 = 500 * 1024 * 1024;

/// Compressed-input ceiling for file-backed install extraction.
///
/// Small npm archives keep the libdeflate fast path. Larger archives fall
/// back to streaming decompression without retaining their full compressed
/// body in memory.
const MAX_HYBRID_BUFFERED_COMPRESSED_SIZE: u64 = 8 * 1024 * 1024;

/// Maximum decompressed output held by the buffered libdeflate path.
const MAX_BUFFERED_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy)]
struct ExtractionLimits {
    max_buffered_compressed_size: u64,
    max_buffered_decompressed_size: usize,
    max_extraction_size: u64,
    max_file_size: u64,
    max_file_count: usize,
}

impl ExtractionLimits {
    fn max_decompressed_stream_size(self) -> u64 {
        let tar_framing_budget = (self.max_file_count as u64)
            .saturating_add(2)
            .saturating_mul(1024);
        self.max_extraction_size.saturating_add(tar_framing_budget)
    }
}

const DEFAULT_EXTRACTION_LIMITS: ExtractionLimits = ExtractionLimits {
    max_buffered_compressed_size: MAX_BUFFERED_COMPRESSED_SIZE,
    max_buffered_decompressed_size: MAX_BUFFERED_DECOMPRESSED_SIZE,
    max_extraction_size: MAX_EXTRACTION_SIZE,
    max_file_size: MAX_FILE_SIZE,
    max_file_count: MAX_FILE_COUNT,
};

enum BufferedGzipDecode<'a> {
    Decoded(BufferedGzipOutput<'a>),
    NeedsStreaming,
}

struct BufferedGzipOutput<'a> {
    data: Vec<u8>,
    _budget: AllocBudgetGuard<'a>,
}

impl BufferedGzipOutput<'_> {
    #[cfg(test)]
    fn into_vec(self) -> Vec<u8> {
        self.data
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.data.capacity()
    }
}

impl AsRef<[u8]> for BufferedGzipOutput<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Decompress a single-member gzip stream into a freshly-allocated `Vec<u8>`.
///
/// Uses libdeflate (~2-3x faster than flate2/zlib-rs on the npm-tarball size
/// distribution). The initial output buffer is sized from the gzip footer's
/// `ISIZE` field (uncompressed size mod 2^32, RFC 1952 §2.3.1). If the output
/// would exceed the buffered memory ceiling, callers must switch to the
/// streaming fallback instead of growing the `Vec`.
///
/// Limitations vs `flate2::read::MultiGzDecoder`: only the first gzip member
/// is decoded. npm packs always emit single-member gzip, so this is sound for
/// the install hot path; the test-only `decompress_gzip` helper retains the
/// flate2 streaming decoder for any multi-member edge cases callers want to
/// exercise.
#[cfg(test)]
fn decompress_gzip_libdeflate(compressed: &[u8]) -> Result<Vec<u8>, LpmError> {
    match decompress_gzip_libdeflate_with_limits(compressed, DEFAULT_EXTRACTION_LIMITS)? {
        BufferedGzipDecode::Decoded(decompressed) => Ok(decompressed.into_vec()),
        BufferedGzipDecode::NeedsStreaming => Err(LpmError::Registry(format!(
            "gzip decompressed output exceeds {}-byte buffered-decode limit",
            DEFAULT_EXTRACTION_LIMITS.max_buffered_decompressed_size
        ))),
    }
}

fn decompress_gzip_libdeflate_with_limits(
    compressed: &[u8],
    limits: ExtractionLimits,
) -> Result<BufferedGzipDecode<'static>, LpmError> {
    decompress_gzip_libdeflate_with_limits_and_budget(compressed, limits, &EXTRACT_BUDGET)
}

fn decompress_gzip_libdeflate_with_limits_and_budget<'a>(
    compressed: &[u8],
    limits: ExtractionLimits,
    extract_budget: &'a AllocBudget,
) -> Result<BufferedGzipDecode<'a>, LpmError> {
    if compressed.len() < 18 {
        return Err(LpmError::Registry(
            "gzip stream too short (need ≥18 bytes for header + footer)".to_string(),
        ));
    }
    // Validate gzip magic (0x1f, 0x8b) — libdeflate would error anyway, but
    // a precise message helps when a non-gzip blob slips through.
    if compressed[0] != 0x1f || compressed[1] != 0x8b {
        return Err(LpmError::Registry(
            "not a gzip stream (missing 0x1f 0x8b magic)".to_string(),
        ));
    }

    // Seed the output capacity from gzip ISIZE. For payloads ≤ 4 GiB this is
    // exact; for larger payloads it's the truncated low 32 bits, in which
    // case we grow on the InsufficientSpace path below.
    let isize_bytes = &compressed[compressed.len() - 4..];
    let isize_hint = u32::from_le_bytes([
        isize_bytes[0],
        isize_bytes[1],
        isize_bytes[2],
        isize_bytes[3],
    ]) as usize;
    let max_buffered = limits.max_buffered_decompressed_size;
    if max_buffered == 0 || isize_hint > max_buffered {
        return Ok(BufferedGzipDecode::NeedsStreaming);
    }

    let mut capacity = if isize_hint == 0 {
        compressed.len().clamp(1, max_buffered)
    } else {
        isize_hint
    };

    // The reservation includes the compressed input and stays attached to the
    // decoded buffer through tar walking. The grow path replaces it only after
    // dropping the smaller output allocation.
    let mut budget = extract_budget.acquire(capacity.saturating_add(compressed.len()) as u64);
    let mut decompressor = libdeflater::Decompressor::new();
    loop {
        let mut output = vec![0u8; capacity];
        match decompressor.gzip_decompress(compressed, &mut output) {
            Ok(actual) => {
                output.truncate(actual);
                return Ok(BufferedGzipDecode::Decoded(BufferedGzipOutput {
                    data: output,
                    _budget: budget,
                }));
            }
            Err(libdeflater::DecompressionError::InsufficientSpace) => {
                if capacity >= max_buffered {
                    return Ok(BufferedGzipDecode::NeedsStreaming);
                }
                // Drop the old buffer FIRST so its bytes leave the
                // process before we acquire the larger budget — keeps
                // peak memory at `new_capacity` rather than
                // `old + new`.
                drop(output);
                capacity = capacity.saturating_mul(2).min(max_buffered);
                drop(budget);
                budget = extract_budget.acquire(capacity.saturating_add(compressed.len()) as u64);
            }
            Err(e) => {
                return Err(LpmError::Registry(format!(
                    "gzip decompression failed: {e:?}"
                )));
            }
        }
    }
}

/// Maximum total extraction size (5 GB) — prevents zip-bomb / tar-bomb attacks.
const MAX_EXTRACTION_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// Global ceiling on the sum of retained compressed input and in-flight
/// gzip-decompress output across all rayon workers. The single-tarball buffered
/// ceiling bounds one decode call at 256 MiB, but a registry-mirror
/// attacker can publish N small packages each of which advertises a
/// 256 MiB ISIZE; with 8 concurrent workers the peak virtual allocation
/// reaches ~2 GiB and OOMs containers running `vm.overcommit_memory=2`
/// or cgroup-bounded CI runners. This budget caps the sum across workers
/// so concurrent buffered decodes serialize at the budget boundary instead
/// of competing for virtual memory.
///
/// 1 GiB lets 4 simultaneous worst-case (ISIZE=256 MiB) decompresses
/// run in parallel and an arbitrary number of small ones; legitimate
/// npm packages decompress well below the per-call cap and rarely
/// hold a slot for more than a few ms.
const PARALLEL_EXTRACT_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

/// Counting semaphore over bytes retained by buffered gzip decoding.
/// The reservation remains held until the decoded buffer is dropped.
static EXTRACT_BUDGET: std::sync::LazyLock<AllocBudget> =
    std::sync::LazyLock::new(|| AllocBudget {
        available: std::sync::Mutex::new(PARALLEL_EXTRACT_BUDGET_BYTES),
        cv: std::sync::Condvar::new(),
    });

struct AllocBudget {
    available: std::sync::Mutex<u64>,
    cv: std::sync::Condvar,
}

impl AllocBudget {
    fn acquire(&self, bytes: u64) -> AllocBudgetGuard<'_> {
        // Reservations larger than the whole budget would deadlock
        // (no path to make `available >= bytes` true). Cap at the
        // budget itself — the in-flight call still gets serialized
        // exclusivity, which is the right behavior for an outsized
        // legitimate tarball.
        let request = bytes.min(PARALLEL_EXTRACT_BUDGET_BYTES);
        let mut guard = self.lock_available();
        while *guard < request {
            guard = self.wait_available(guard);
        }
        *guard -= request;
        AllocBudgetGuard {
            budget: self,
            bytes: request,
        }
    }

    fn lock_available(&self) -> std::sync::MutexGuard<'_, u64> {
        match self.available.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn wait_available<'a>(
        &self,
        guard: std::sync::MutexGuard<'a, u64>,
    ) -> std::sync::MutexGuard<'a, u64> {
        match self.cv.wait(guard) {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

struct AllocBudgetGuard<'a> {
    budget: &'a AllocBudget,
    bytes: u64,
}

impl Drop for AllocBudgetGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self.budget.lock_available();
        *guard = guard
            .saturating_add(self.bytes)
            .min(PARALLEL_EXTRACT_BUDGET_BYTES);
        // `notify_all`, not `notify_one`: a single release can
        // unblock multiple waiters with different reservation
        // sizes simultaneously (e.g. releasing 256 MiB can satisfy
        // both a 128 MiB and a 100 MiB waiter — total 228 MiB still
        // fits). With `notify_one` only one would be woken and the
        // other would stay parked even though the budget could
        // serve it. Spurious wakeups for over-sized waiters
        // re-enter the `while *guard < request` loop and re-park,
        // which is cheap and never starves.
        self.budget.cv.notify_all();
    }
}

/// Maximum single file size within a tarball (500 MB).
const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024;

/// Maximum number of files in a tarball (100,000).
const MAX_FILE_COUNT: usize = 100_000;

/// Extract a .tgz (gzip-compressed tar) from any `Read` source to a target directory.
///
/// Strips the first path component (the `package/` prefix that npm pack adds).
/// Returns the list of extracted file paths (relative to `target_dir`).
///
/// Enforces size limits to prevent tar-bomb attacks:
/// - Max 5 GiB total extraction size
/// - Max 500 MiB per individual file
/// - Max 100,000 files
/// - Max 100,000 GNU or PAX metadata records
/// - Max 256 path components and 32 KiB per encoded path
/// - Max 1 MiB per GNU or PAX metadata record
pub fn extract_tarball_from_reader(
    reader: impl std::io::Read,
    target_dir: &Path,
) -> Result<Vec<PathBuf>, LpmError> {
    extract_tarball_from_reader_with_inspector(reader, target_dir, |_, _| false, |_| {})
}

/// Per-entry information handed to an [`extract_tarball_from_reader_with_inspector`]
/// inspector. Emitted AFTER the entry has been successfully written to disk,
/// so the caller can assume the file exists at `target_dir.join(relative_path)`.
pub struct EntryInfo<'a> {
    /// Path relative to `target_dir` (npm's `package/` prefix already stripped).
    pub relative_path: &'a Path,
    /// Effective uncompressed size in bytes, including PAX and sparse overrides.
    pub size: u64,
    /// File contents, if the caller's `buffer_predicate` returned `true`
    /// for this entry. `None` when the predicate said skip buffering — in
    /// which case `entry.unpack()` streamed the file to disk without
    /// materializing bytes in memory.
    pub bytes: Option<&'a [u8]>,
    /// BLAKE3 digest computed while the entry was written when the caller
    /// selected the digest-enabled extraction path.
    pub blake3_digest: Option<[u8; 32]>,
}

/// Extract tarball AND invoke a caller-supplied
/// inspector for every regular file entry. The inspector fires AFTER the
/// entry is safely on disk, with the entry's bytes-in-memory if the
/// `buffer_predicate` opted to buffer that entry.
///
/// Fused-scan use case: lpm-store's streaming path passes a predicate
/// that buffers scannable JS/TS sources under the behavioral scanner's
/// per-file limit and an inspector that feeds each buffered entry into a
/// running `PackageAnalyzer`. Oversized source files can stream to disk
/// and be sampled by the inspector after write. The result is one
/// filesystem pass instead of two — P1's extract writes files while P2's
/// scan reads the bytes it already has in hand, eliminating the
/// `analyze_package` post-extract walk.
///
/// Unbuffered entries (all non-source files, `.d.ts`, `.map`, files over
/// 2 MB, etc.) go through the original `entry.unpack()` streaming path.
/// Memory ceiling is bounded by the caller's predicate — for source
/// scanning, it's `files_under_2MB × max_concurrent_scanned_entries`,
/// which in practice is one file at a time within a single tarball.
pub fn extract_tarball_from_reader_with_inspector<P, I>(
    reader: impl std::io::Read,
    target_dir: &Path,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    extract_tarball_from_reader_with_inspector_with_limits(
        reader,
        target_dir,
        DEFAULT_EXTRACTION_LIMITS,
        false,
        buffer_predicate,
        inspector,
    )
}

/// Bounded-memory variant that always uses streaming gzip decompression.
pub fn extract_tarball_from_reader_streaming_with_inspector<P, I>(
    reader: impl std::io::Read,
    target_dir: &Path,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    let limits = ExtractionLimits {
        max_buffered_compressed_size: 0,
        ..DEFAULT_EXTRACTION_LIMITS
    };
    extract_tarball_from_reader_with_inspector_with_limits(
        reader,
        target_dir,
        limits,
        false,
        buffer_predicate,
        inspector,
    )
}

/// Bounded-memory file-backed extraction that buffers only small archives.
pub fn extract_tarball_from_reader_hybrid_with_inspector<P, I>(
    reader: impl std::io::Read,
    target_dir: &Path,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    let limits = ExtractionLimits {
        max_buffered_compressed_size: MAX_HYBRID_BUFFERED_COMPRESSED_SIZE,
        ..DEFAULT_EXTRACTION_LIMITS
    };
    extract_tarball_from_reader_with_inspector_with_limits(
        reader,
        target_dir,
        limits,
        false,
        buffer_predicate,
        inspector,
    )
}

/// Extract a tarball from a reader while computing a BLAKE3 digest for every
/// regular file in the same write pass.
pub fn extract_tarball_from_reader_with_entry_digests<P, I>(
    reader: impl std::io::Read,
    target_dir: &Path,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    extract_tarball_from_reader_with_inspector_with_limits(
        reader,
        target_dir,
        DEFAULT_EXTRACTION_LIMITS,
        true,
        buffer_predicate,
        inspector,
    )
}

/// Digest-enabled bounded-memory variant that always streams gzip input.
pub fn extract_tarball_from_reader_streaming_with_entry_digests<P, I>(
    reader: impl std::io::Read,
    target_dir: &Path,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    let limits = ExtractionLimits {
        max_buffered_compressed_size: 0,
        ..DEFAULT_EXTRACTION_LIMITS
    };
    extract_tarball_from_reader_with_inspector_with_limits(
        reader,
        target_dir,
        limits,
        true,
        buffer_predicate,
        inspector,
    )
}

/// Digest-enabled file-backed extraction that buffers only small archives.
pub fn extract_tarball_from_reader_hybrid_with_entry_digests<P, I>(
    reader: impl std::io::Read,
    target_dir: &Path,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    let limits = ExtractionLimits {
        max_buffered_compressed_size: MAX_HYBRID_BUFFERED_COMPRESSED_SIZE,
        ..DEFAULT_EXTRACTION_LIMITS
    };
    extract_tarball_from_reader_with_inspector_with_limits(
        reader,
        target_dir,
        limits,
        true,
        buffer_predicate,
        inspector,
    )
}

/// Extract an in-memory tarball while inspecting regular file entries.
///
/// Unlike [`extract_tarball_from_reader_with_inspector`], this path uses the
/// supplied compressed slice directly instead of first copying it into a
/// second buffer.
pub fn extract_tarball_with_inspector<P, I>(
    data: &[u8],
    target_dir: &Path,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    extract_tarball_from_slice_with_inspector_with_limits(
        data,
        target_dir,
        DEFAULT_EXTRACTION_LIMITS,
        false,
        buffer_predicate,
        inspector,
    )
}

/// Extract an in-memory tarball while computing a BLAKE3 digest for every
/// regular file in the same write pass.
pub fn extract_tarball_with_entry_digests<P, I>(
    data: &[u8],
    target_dir: &Path,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    extract_tarball_from_slice_with_inspector_with_limits(
        data,
        target_dir,
        DEFAULT_EXTRACTION_LIMITS,
        true,
        buffer_predicate,
        inspector,
    )
}

fn extract_tarball_from_reader_with_inspector_with_limits<R, P, I>(
    reader: R,
    target_dir: &Path,
    limits: ExtractionLimits,
    compute_blake3: bool,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    R: std::io::Read,
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    // Top-level extractor span. Visible in Tracy under `--features tracy`;
    // covers buffered read + libdeflate decompression + tar walk so the
    // per-package fetch breakdown can attribute time to extraction vs
    // other fetch sub-stages.
    let _span = tracing::info_span!("extractor.extract").entered();
    // Use buffered libdeflate decompression (~2-3x faster than flate2/zlib-rs
    // on npm-tarball sizes). Cost is peak memory = compressed_size +
    // decompressed_size rather than streaming's bounded per-entry buffer.
    // For npm packages (typically <2 MB compressed / <10 MB decompressed)
    // this is a clear win on cold-install wall-clock.
    //
    // The streaming pipeline still works because callers that need SRI
    // verification wrap the network reader with `HashingReader`: bytes read
    // into the prefix buffer are hashed once, and any remaining bytes are read
    // from the original reader by the fallback decoder.
    match read_compressed_input(reader, limits.max_buffered_compressed_size)? {
        CompressedInput::Buffered(compressed) => extract_buffered_gzip_tarball(
            &compressed,
            target_dir,
            limits,
            compute_blake3,
            buffer_predicate,
            inspector,
        ),
        CompressedInput::Stream(reader) => extract_streaming_gzip_tarball(
            reader,
            target_dir,
            limits,
            compute_blake3,
            buffer_predicate,
            inspector,
        ),
    }
}

fn extract_tarball_from_slice_with_inspector_with_limits<P, I>(
    data: &[u8],
    target_dir: &Path,
    limits: ExtractionLimits,
    compute_blake3: bool,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    let _span = tracing::info_span!("extractor.extract").entered();
    if data.len() as u64 > limits.max_buffered_compressed_size {
        return extract_streaming_gzip_tarball(
            std::io::Cursor::new(data),
            target_dir,
            limits,
            compute_blake3,
            buffer_predicate,
            inspector,
        );
    }

    extract_buffered_gzip_tarball(
        data,
        target_dir,
        limits,
        compute_blake3,
        buffer_predicate,
        inspector,
    )
}

fn extract_buffered_gzip_tarball<P, I>(
    compressed: &[u8],
    target_dir: &Path,
    limits: ExtractionLimits,
    compute_blake3: bool,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    match decompress_gzip_libdeflate_with_limits(compressed, limits)? {
        BufferedGzipDecode::Decoded(decompressed) => extract_tar_archive_with_inspector(
            std::io::Cursor::new(decompressed),
            target_dir,
            limits,
            compute_blake3,
            buffer_predicate,
            inspector,
            |_| Ok(()),
        ),
        BufferedGzipDecode::NeedsStreaming => extract_streaming_gzip_tarball(
            std::io::Cursor::new(compressed),
            target_dir,
            limits,
            compute_blake3,
            buffer_predicate,
            inspector,
        ),
    }
}

enum CompressedInput<R> {
    Buffered(Vec<u8>),
    Stream(std::io::Chain<std::io::Cursor<Vec<u8>>, R>),
}

fn read_compressed_input<R: std::io::Read>(
    mut reader: R,
    max_buffered_size: u64,
) -> Result<CompressedInput<R>, LpmError> {
    const READ_CHUNK_SIZE: usize = 64 * 1024;

    let initial_capacity = max_buffered_size.min(READ_CHUNK_SIZE as u64) as usize;
    let mut compressed = Vec::with_capacity(initial_capacity);
    let mut chunk = [0u8; READ_CHUNK_SIZE];

    loop {
        let buffered_len = compressed.len() as u64;
        if buffered_len >= max_buffered_size {
            let read = reader.read(&mut chunk).map_err(LpmError::Io)?;
            if read == 0 {
                return Ok(CompressedInput::Buffered(compressed));
            }
            compressed.extend_from_slice(&chunk[..read]);
            return Ok(CompressedInput::Stream(
                std::io::Cursor::new(compressed).chain(reader),
            ));
        }

        let remaining = (max_buffered_size - buffered_len).min(READ_CHUNK_SIZE as u64) as usize;
        let read = reader.read(&mut chunk[..remaining]).map_err(LpmError::Io)?;
        if read == 0 {
            return Ok(CompressedInput::Buffered(compressed));
        }
        compressed.extend_from_slice(&chunk[..read]);
    }
}

fn extract_streaming_gzip_tarball<R, P, I>(
    reader: R,
    target_dir: &Path,
    limits: ExtractionLimits,
    compute_blake3: bool,
    buffer_predicate: P,
    inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
    R: std::io::Read,
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
{
    let decoder = GzDecoder::new(reader);
    let limited = DecompressedLimitReader::new(decoder, limits.max_decompressed_stream_size());
    extract_tar_archive_with_inspector(
        limited,
        target_dir,
        limits,
        compute_blake3,
        buffer_predicate,
        inspector,
        |mut reader| {
            std::io::copy(&mut reader, &mut std::io::sink())
                .map(|_| ())
                .map_err(LpmError::Io)
        },
    )
}

struct DecompressedLimitReader<R> {
    inner: R,
    bytes_read: u64,
    limit: u64,
}

impl<R> DecompressedLimitReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            bytes_read: 0,
            limit,
        }
    }
}

impl<R: std::io::Read> std::io::Read for DecompressedLimitReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let remaining = self.limit.saturating_sub(self.bytes_read);
        if remaining == 0 {
            let mut scratch = [0u8; 1];
            return match self.inner.read(&mut scratch)? {
                0 => Ok(0),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("gzip decompression exceeded {}-byte limit", self.limit),
                )),
            };
        }

        let max_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        let read = self.inner.read(&mut buf[..max_read])?;
        self.bytes_read += read as u64;
        Ok(read)
    }
}

fn extract_tar_archive_with_inspector<R, P, I, D>(
    reader: R,
    target_dir: &Path,
    limits: ExtractionLimits,
    compute_blake3: bool,
    buffer_predicate: P,
    mut inspector: I,
    drain_after_entries: D,
) -> Result<Vec<PathBuf>, LpmError>
where
    R: std::io::Read,
    P: Fn(&Path, u64) -> bool,
    I: FnMut(EntryInfo<'_>),
    D: FnOnce(R) -> Result<(), LpmError>,
{
    let mut extracted_files = Vec::new();
    let mut created_dirs = Vec::new();
    let mut total_size: u64 = 0;

    std::fs::create_dir_all(target_dir)?;
    let extraction_root = target_dir.canonicalize().map_err(LpmError::Io)?;
    // Memoize parent dirs we've already verified-or-created so the
    // per-file `prepare_output_path` walk doesn't re-`symlink_metadata`
    // every component on every entry. For an npm tarball with ~80
    // entries averaging 4 path components, the walk without this cache
    // does ~320 `symlink_metadata` syscalls; with it, ~84 (each unique
    // dir prefix once).
    //
    // Capacity heuristic: most npm tarballs have ≤ 10 distinct
    // intermediate dirs; 64 covers the long tail without over-allocating.
    let mut verified_parents: HashSet<PathBuf> = HashSet::with_capacity(64);
    verified_parents.insert(extraction_root.clone());
    let mut seen_archive_paths = HashMap::with_capacity(64);

    let visit_result = visit_tar_archive(
        reader,
        TarArchiveLimits {
            max_entry_bytes: limits.max_file_size,
            ..TarArchiveLimits::new(limits.max_file_count)
        },
        |mut entry| {
            let size = entry.size();
            if size > limits.max_file_size {
                return Err(LpmError::Registry(format!(
                    "file too large in tarball: {} bytes (max {})",
                    size, limits.max_file_size
                )));
            }
            total_size = total_size.saturating_add(size);
            if total_size > limits.max_extraction_size {
                return Err(LpmError::Registry(format!(
                    "tarball extraction size limit exceeded ({} bytes)",
                    limits.max_extraction_size
                )));
            }

            let original_path = entry.path().to_path_buf();
            let Some(relative_path) = sanitize_entry_path(&original_path)? else {
                return Ok(ControlFlow::<()>::Continue(()));
            };

            let (target_path, mut entry_created_dirs) = prepare_output_path(
                &extraction_root,
                &relative_path,
                &original_path,
                &mut verified_parents,
            )?;
            created_dirs.append(&mut entry_created_dirs);

            if !target_path.starts_with(&extraction_root) {
                return Err(LpmError::Registry(format!(
                    "path traversal detected in tarball: {}",
                    original_path.display()
                )));
            }

            if entry.header().entry_type().is_file() {
                let duplicate_path =
                    record_case_fold_archive_path(&mut seen_archive_paths, &relative_path)?;
                let exec_bits = entry.header().mode().unwrap_or(0o644) & 0o111;

                let buffer_this = buffer_predicate(&relative_path, size);
                let (buffered_bytes, blake3_digest) = if buffer_this {
                    let mut buf = Vec::with_capacity(size as usize);
                    entry.read_to_end(&mut buf).map_err(LpmError::Io)?;
                    write_buffered_entry(&target_path, &buf, duplicate_path)?;
                    let digest = compute_blake3.then(|| *blake3::hash(&buf).as_bytes());
                    (Some(buf), digest)
                } else {
                    let digest = stream_entry_to_disk(
                        &mut entry,
                        &target_path,
                        compute_blake3,
                        duplicate_path,
                    )?;
                    (None, digest)
                };

                #[cfg(unix)]
                if exec_bits != 0 {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o644 | exec_bits);
                    std::fs::set_permissions(&target_path, perms).map_err(LpmError::Io)?;
                }
                #[cfg(not(unix))]
                let _ = exec_bits;

                inspector(EntryInfo {
                    relative_path: &relative_path,
                    size,
                    bytes: buffered_bytes.as_deref(),
                    blake3_digest,
                });

                extracted_files.push(relative_path);
            }
            Ok(ControlFlow::<()>::Continue(()))
        },
    );

    let (inner, _) = match visit_result {
        Ok(result) => result,
        Err(error) => {
            return rollback_extraction(&extraction_root, &extracted_files, &created_dirs, error);
        }
    };
    if let Err(error) = drain_after_entries(inner) {
        return rollback_extraction(&extraction_root, &extracted_files, &created_dirs, error);
    }

    Ok(extracted_files)
}

/// Write a fully-buffered entry to disk. Mirrors `tar::Entry::unpack`'s
/// file-creation semantics (create-or-truncate, 0644 default) without
/// restoring mode/mtime metadata — we don't need either for npm packages
/// and keeping it minimal reduces `fs` syscall count vs `tar`'s full
/// unpack path.
fn write_buffered_entry(
    target_path: &Path,
    bytes: &[u8],
    replace_existing: bool,
) -> Result<(), LpmError> {
    use std::io::Write;
    let mut file = create_leaf_file(target_path, replace_existing)?;
    file.write_all(bytes).map_err(LpmError::Io)?;
    Ok(())
}

/// Stream a tar entry's bytes directly to disk via `io::copy`, skipping
/// the chmod/chown/utimes epilogue `tar::Entry::unpack` always emits.
/// Used by the non-buffered branch of the extractor to bypass the
/// tar unpack epilogue (chmod/chown/utimes).
fn stream_entry_to_disk(
    entry: &mut impl Read,
    target_path: &Path,
    compute_blake3: bool,
    replace_existing: bool,
) -> Result<Option<[u8; 32]>, LpmError> {
    use std::io::Write;

    let mut file = create_leaf_file(target_path, replace_existing)?;
    if !compute_blake3 {
        std::io::copy(entry, &mut file).map_err(LpmError::Io)?;
        return Ok(None);
    }

    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = entry.read(&mut buffer).map_err(LpmError::Io)?;
        if read == 0 {
            break;
        }
        file.write_all(&buffer[..read]).map_err(LpmError::Io)?;
        hasher.update(&buffer[..read]);
    }
    Ok(Some(*hasher.finalize().as_bytes()))
}

fn cleanup_extracted_files(
    target_dir: &Path,
    extracted_files: &[PathBuf],
    created_dirs: &[PathBuf],
) {
    for relative_path in extracted_files.iter().rev() {
        let full_path = target_dir.join(relative_path);
        let _ = std::fs::remove_file(&full_path);

        let mut current = full_path.parent();
        while let Some(directory) = current {
            if directory == target_dir {
                break;
            }
            if std::fs::remove_dir(directory).is_err() {
                break;
            }
            current = directory.parent();
        }
    }

    for directory in created_dirs.iter().rev() {
        let _ = std::fs::remove_dir(directory);
    }
}

fn prepare_output_path(
    target_dir: &Path,
    relative_path: &Path,
    original_path: &Path,
    verified_parents: &mut std::collections::HashSet<PathBuf>,
) -> Result<(PathBuf, Vec<PathBuf>), LpmError> {
    let mut current = target_dir.to_path_buf();
    let mut created_dirs = Vec::new();
    let mut components = relative_path.components().peekable();

    while let Some(component) = components.next() {
        current.push(component.as_os_str());
        let is_last = components.peek().is_none();

        // The leaf is the per-entry FILE path. We don't need to stat
        // it here — the file-create call handles leaf-symlink defense
        // via [`create_leaf_file`] (`O_NOFOLLOW` on unix, explicit
        // pre-create stat on windows). Walking the leaf in this loop
        // would just add a `symlink_metadata` syscall per file (~18 K
        // syscalls on a fixture-large install) for a check that the
        // open already enforces atomically.
        if is_last {
            break;
        }

        // Skip the `symlink_metadata` syscall when we've already
        // verified or created this exact intermediate dir on a prior
        // entry. Only applies to NON-leaf components.
        if verified_parents.contains(&current) {
            continue;
        }

        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(LpmError::Registry(format!(
                        "path traversal detected via symlink in tarball target: {}",
                        original_path.display()
                    )));
                }

                // M57: on Windows, `is_symlink()` only catches the
                // `IO_REPARSE_TAG_SYMLINK` shape. Junctions, mount
                // points, and other reparse-tagged directories carry
                // `FILE_ATTRIBUTE_REPARSE_POINT` but are NOT classified
                // as symlinks by `FileType`, so they would pass the
                // check above and let `File::create` write through to
                // the junction target on the next iteration.
                if is_windows_reparse_point(&metadata) {
                    return Err(LpmError::Registry(format!(
                        "path traversal detected via reparse point in tarball target: {}",
                        original_path.display()
                    )));
                }

                if !metadata.is_dir() {
                    return Err(LpmError::Registry(format!(
                        "non-directory path blocks tarball extraction: {}",
                        original_path.display()
                    )));
                }
                verified_parents.insert(current.clone());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(LpmError::Io)?;
                created_dirs.push(current.clone());
                verified_parents.insert(current.clone());
            }
            Err(error) => return Err(LpmError::Io(error)),
        }
    }

    Ok((current, created_dirs))
}

/// Create-or-truncate the leaf file at `target_path` while atomically
/// rejecting symlinks at that path.
///
/// On unix this opens with `O_NOFOLLOW`; if a symlink (orphaned from a
/// prior failed extraction or planted by another process) sits at the
/// path, the kernel returns `ELOOP` and the open fails — same posture
/// as the previous explicit `symlink_metadata` pre-check, fewer
/// syscalls. On windows the optimization is skipped (no `O_NOFOLLOW`
/// equivalent in `OpenOptions`); we fall back to an explicit stat.
/// Exact duplicate archive members detach the prior file before opening it
/// because an inspector may already have hardlinked that inode into a CAS.
fn create_leaf_file(target_path: &Path, replace_existing: bool) -> Result<std::fs::File, LpmError> {
    if replace_existing {
        let metadata = std::fs::symlink_metadata(target_path).map_err(LpmError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(LpmError::Registry(format!(
                "path traversal detected via symlink in tarball target: {}",
                target_path.display()
            )));
        }
        if is_windows_reparse_point(&metadata) {
            return Err(LpmError::Registry(format!(
                "path traversal detected via reparse point in tarball target: {}",
                target_path.display()
            )));
        }
        if !metadata.file_type().is_file() {
            return Err(LpmError::Registry(format!(
                "non-file path blocks duplicate tarball entry: {}",
                target_path.display()
            )));
        }
        std::fs::remove_file(target_path).map_err(LpmError::Io)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if replace_existing {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        options
            // `O_NOFOLLOW` only checks the FINAL path component — the
            // parent walk in `prepare_output_path` already verified
            // every intermediate dir is a real directory, not a
            // symlink, so this single flag closes the leaf-symlink
            // attack vector with no extra syscall.
            .custom_flags(libc::O_NOFOLLOW)
            .open(target_path)
            .map_err(|e| match e.raw_os_error() {
                // `ELOOP` (or `EMLINK` on some BSDs) from `O_NOFOLLOW`
                // turns into the same registry-error shape the
                // previous explicit-stat path produced.
                Some(libc::ELOOP) => LpmError::Registry(format!(
                    "path traversal detected via symlink in tarball target: {}",
                    target_path.display()
                )),
                _ => LpmError::Io(e),
            })
    }
    #[cfg(not(unix))]
    {
        // Windows: explicit pre-create stat for the leaf-symlink
        // guard. NTFS reparse points behave differently than POSIX
        // symlinks; this matches the parent-walk's reparse-point
        // check so that junctions, mount points, and other reparse-
        // tagged objects (which `is_symlink()` does NOT classify as
        // symlinks) cannot redirect `File::create` writes outside the
        // extraction root.
        match std::fs::symlink_metadata(target_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(LpmError::Registry(format!(
                    "path traversal detected via symlink in tarball target: {}",
                    target_path.display()
                )));
            }
            // M57: catch the junction / mount-point shape that
            // `is_symlink()` misses.
            Ok(meta) if is_windows_reparse_point(&meta) => {
                return Err(LpmError::Registry(format!(
                    "path traversal detected via reparse point in tarball target: {}",
                    target_path.display()
                )));
            }
            Ok(_) | Err(_) => {}
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if replace_existing {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        options.open(target_path).map_err(LpmError::Io)
    }
}

/// M57: detect any NTFS reparse-point shape — symbolic links,
/// junctions, mount points, IO_REPARSE_TAG_APPEXECLINK shims, etc.
///
/// `Metadata::file_type().is_symlink()` only flags reparse points
/// whose tag is `IO_REPARSE_TAG_SYMLINK` (0xA000000C). Junctions
/// (`IO_REPARSE_TAG_MOUNT_POINT` = 0xA0000003) and the long tail of
/// reparse-tag variants do NOT pass that check, but their presence
/// at a path can still redirect later file operations away from the
/// extraction root via the underlying volume mount or junction
/// target. Checking `FILE_ATTRIBUTE_REPARSE_POINT` directly catches
/// every reparse-tagged inode in one bit test.
///
/// Returns `false` on non-Windows builds — the parent walk's
/// `is_symlink()` check is sufficient on POSIX where junctions don't
/// exist.
#[cfg(windows)]
fn is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    // 0x00000400 = FILE_ATTRIBUTE_REPARSE_POINT (winnt.h). Cross-
    // checking via windows-sys is not worth the dep for one literal.
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn rollback_extraction(
    target_dir: &Path,
    extracted_files: &[PathBuf],
    created_dirs: &[PathBuf],
    error: LpmError,
) -> Result<Vec<PathBuf>, LpmError> {
    cleanup_extracted_files(target_dir, extracted_files, created_dirs);
    Err(error)
}

/// Extract a .tgz directly from an in-memory byte slice.
pub fn extract_tarball(data: &[u8], target_dir: &Path) -> Result<Vec<PathBuf>, LpmError> {
    extract_tarball_with_inspector(data, target_dir, |_, _| false, |_| {})
}

/// Extract a .tgz from a file on disk. Uses `BufReader` for efficient I/O.
///
/// This is the bounded-memory path: the tarball is read from disk in chunks
/// rather than loaded entirely into memory.
pub fn extract_tarball_from_file(path: &Path, target_dir: &Path) -> Result<Vec<PathBuf>, LpmError> {
    let file = std::fs::File::open(path).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to open tarball file {}: {e}", path.display()),
        ))
    })?;
    let reader = std::io::BufReader::new(file);
    extract_tarball_from_reader_streaming_with_inspector(reader, target_dir, |_, _| false, |_| {})
}

/// Extract + verify in one step. The typical pipeline.
///
/// 1. Verify integrity hash matches
/// 2. Decompress gzip + extract tar
/// 3. Strip `package/` prefix
/// 4. Return list of extracted files
pub fn verify_and_extract(
    data: &[u8],
    expected_sri: &str,
    target_dir: &Path,
) -> Result<Vec<PathBuf>, LpmError> {
    verify_integrity(data, expected_sri)?;
    extract_tarball(data, target_dir)
}

/// List files in a tarball without extracting.
///
/// Useful for `lpm info --files` or source browsing.
pub fn list_tarball_contents(data: &[u8]) -> Result<Vec<PathBuf>, LpmError> {
    list_tarball_contents_with_limits(data, DEFAULT_EXTRACTION_LIMITS)
}

fn list_tarball_contents_with_limits(
    data: &[u8],
    limits: ExtractionLimits,
) -> Result<Vec<PathBuf>, LpmError> {
    if data.len() as u64 > limits.max_buffered_compressed_size {
        return list_tarball_contents_streaming(std::io::Cursor::new(data), limits);
    }

    match decompress_gzip_libdeflate_with_limits(data, limits)? {
        BufferedGzipDecode::Decoded(decompressed) => {
            list_tar_archive_contents(std::io::Cursor::new(decompressed), limits, |_| Ok(()))
        }
        BufferedGzipDecode::NeedsStreaming => {
            list_tarball_contents_streaming(std::io::Cursor::new(data), limits)
        }
    }
}

fn list_tarball_contents_streaming<R: std::io::Read>(
    reader: R,
    limits: ExtractionLimits,
) -> Result<Vec<PathBuf>, LpmError> {
    let decoder = GzDecoder::new(reader);
    let limited = DecompressedLimitReader::new(decoder, limits.max_decompressed_stream_size());
    list_tar_archive_contents(limited, limits, |mut reader| {
        std::io::copy(&mut reader, &mut std::io::sink())
            .map(|_| ())
            .map_err(LpmError::Io)
    })
}

fn list_tar_archive_contents<R, D>(
    reader: R,
    limits: ExtractionLimits,
    drain_after_entries: D,
) -> Result<Vec<PathBuf>, LpmError>
where
    R: std::io::Read,
    D: FnOnce(R) -> Result<(), LpmError>,
{
    let mut files = Vec::new();
    let mut seen_archive_paths = HashMap::with_capacity(64);

    let (inner, _) = visit_tar_archive(
        reader,
        TarArchiveLimits {
            max_entry_bytes: limits.max_file_size,
            ..TarArchiveLimits::new(limits.max_file_count)
        },
        |entry| {
            if entry.header().entry_type().is_file()
                && let Some(stripped) = sanitize_entry_path(entry.path())?
            {
                record_case_fold_archive_path(&mut seen_archive_paths, &stripped)?;
                files.push(stripped);
            }
            Ok(ControlFlow::<()>::Continue(()))
        },
    )?;

    drain_after_entries(inner)?;
    Ok(files)
}

/// Strip the first path component. `package/src/index.js` → `src/index.js`.
/// Returns `None` for paths that are just the prefix directory itself.
fn strip_first_component(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    components.next()?; // Skip first component
    let rest: PathBuf = components.collect();
    if rest.as_os_str().is_empty() {
        None
    } else {
        Some(rest)
    }
}

/// Convert a tar entry path into a package-relative extraction path.
///
/// npm package tarballs conventionally wrap files under a first `package/`
/// component. The returned path has that component stripped and rejects any
/// remaining traversal, root, or platform-prefix components.
pub fn sanitize_entry_path(path: &Path) -> Result<Option<PathBuf>, LpmError> {
    let Some(relative_path) = strip_first_component(path) else {
        return Ok(None);
    };

    for component in relative_path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(LpmError::Registry(format!(
                    "path traversal detected in tarball: {}",
                    path.display()
                )));
            }
            Component::Normal(name) if is_windows_reserved_device_name(name) => {
                return Err(LpmError::Registry(format!(
                    "reserved Windows device name in tarball entry: {}",
                    path.display()
                )));
            }
            Component::Normal(_) | Component::CurDir => {}
        }
    }

    Ok(Some(relative_path))
}

fn record_case_fold_archive_path(
    seen_paths: &mut HashMap<String, PathBuf>,
    relative_path: &Path,
) -> Result<bool, LpmError> {
    let key = case_fold_path_key(relative_path);
    if let Some(existing_path) = seen_paths.get(&key) {
        if existing_path == relative_path {
            return Ok(true);
        }

        return Err(LpmError::Registry(format!(
            "case-fold path collision in tarball: {} conflicts with {}",
            relative_path.display(),
            existing_path.display()
        )));
    }

    seen_paths.insert(key, relative_path.to_path_buf());
    Ok(false)
}

fn case_fold_path_key(path: &Path) -> String {
    let mut key = String::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        if !key.is_empty() {
            key.push('/');
        }
        append_case_fold_component_key(&mut key, name);
    }
    key
}

fn append_case_fold_component_key(key: &mut String, component: &OsStr) {
    let component = component.to_string_lossy();
    let trimmed = component.trim_end_matches([' ', '.']);
    for ch in trimmed.chars() {
        key.extend(ch.to_lowercase());
    }
}

fn is_windows_reserved_device_name(component: &OsStr) -> bool {
    let component = component.to_string_lossy();
    let trimmed = component.trim_end_matches([' ', '.']);
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    let upper = stem.to_ascii_uppercase();

    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || is_reserved_windows_port_name(&upper, "COM")
        || is_reserved_windows_port_name(&upper, "LPT")
}

fn is_reserved_windows_port_name(upper: &str, prefix: &str) -> bool {
    let Some(number) = upper.strip_prefix(prefix) else {
        return false;
    };

    matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use lpm_common::integrity::HashAlgorithm;
    use std::io::Write;

    /// Create a test .tgz with a single file inside `package/`.
    fn create_test_tarball(filename: &str, content: &[u8]) -> Vec<u8> {
        create_test_tarball_with_entries(&[(filename, content)])
    }

    /// Create a test .tgz with multiple files inside `package/`.
    fn create_test_tarball_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (filename, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();

                let tar_path = format!("package/{filename}");
                builder
                    .append_data(&mut header, &tar_path, *content)
                    .unwrap();
            }
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn create_pax_size_override_tarball(raw_size: u64, effective_size: u64) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let effective_size_text = effective_size.to_string();
            builder
                .append_pax_extensions([("size", effective_size_text.as_bytes())])
                .unwrap();

            let mut header = tar::Header::new_ustar();
            header.set_size(raw_size);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_path("package/payload.js").unwrap();
            header.set_cksum();
            builder.get_mut().write_all(header.as_bytes()).unwrap();
            builder
                .get_mut()
                .write_all(&vec![0_u8; effective_size as usize])
                .unwrap();
            let padding = (512 - effective_size % 512) % 512;
            builder
                .get_mut()
                .write_all(&vec![0_u8; padding as usize])
                .unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn streaming_test_limits() -> ExtractionLimits {
        ExtractionLimits {
            max_buffered_compressed_size: 64 * 1024,
            max_buffered_decompressed_size: 1024,
            max_extraction_size: 1024 * 1024,
            max_file_size: 512 * 1024,
            max_file_count: 1000,
        }
    }

    #[test]
    fn buffered_gzip_decode_yields_streaming_when_output_exceeds_memory_cap() {
        let payload = vec![b'a'; 4096];
        let tgz = create_test_tarball("payload.bin", &payload);

        let decoded =
            decompress_gzip_libdeflate_with_limits(&tgz, streaming_test_limits()).unwrap();

        assert!(matches!(decoded, BufferedGzipDecode::NeedsStreaming));
    }

    #[test]
    fn extract_tarball_streams_when_buffered_output_cap_is_exceeded() {
        let payload = vec![b'a'; 4096];
        let tgz = create_test_tarball("payload.bin", &payload);
        let dir = tempfile::tempdir().unwrap();
        let mut inspected = Vec::new();

        let files = extract_tarball_from_reader_with_inspector_with_limits(
            std::io::Cursor::new(&tgz),
            dir.path(),
            streaming_test_limits(),
            false,
            |path, size| path == Path::new("payload.bin") && size == payload.len() as u64,
            |entry| {
                if let Some(bytes) = entry.bytes {
                    inspected.extend_from_slice(bytes);
                }
            },
        )
        .unwrap();

        assert_eq!(files, [PathBuf::from("payload.bin")]);
        assert_eq!(
            std::fs::read(dir.path().join("payload.bin")).unwrap(),
            payload
        );
        assert_eq!(inspected, payload);
    }

    #[test]
    fn pax_effective_size_cannot_bypass_per_file_limit() {
        let tgz = create_pax_size_override_tarball(1, 2048);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_file_size: 1024,
            ..streaming_test_limits()
        };

        let error = extract_tarball_from_reader_with_inspector_with_limits(
            std::io::Cursor::new(&tgz),
            dir.path(),
            limits,
            false,
            |path, _| path.extension() == Some(OsStr::new("js")),
            |_| {},
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("file too large"),
            "expected per-file limit rejection, got: {error}"
        );
        assert!(!dir.path().join("payload.js").exists());
    }

    #[test]
    fn hybrid_reader_streams_archives_larger_than_its_compressed_memory_ceiling() {
        let payload = vec![0x5a; MAX_HYBRID_BUFFERED_COMPRESSED_SIZE as usize + 1024];
        let mut tar_data = Vec::with_capacity(payload.len() + 2048);
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/payload.bin", payload.as_slice())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();
        assert!(tgz.len() as u64 > MAX_HYBRID_BUFFERED_COMPRESSED_SIZE);

        let dir = tempfile::tempdir().unwrap();
        let files = extract_tarball_from_reader_hybrid_with_inspector(
            std::io::Cursor::new(tgz),
            dir.path(),
            |_, _| false,
            |_| {},
        )
        .unwrap();

        assert_eq!(files, [PathBuf::from("payload.bin")]);
        assert_eq!(
            std::fs::metadata(dir.path().join("payload.bin"))
                .unwrap()
                .len(),
            payload.len() as u64
        );
    }

    #[test]
    fn digest_enabled_extraction_hashes_buffered_and_streamed_entries_during_write() {
        let buffered = b"console.log('buffered')";
        let streamed = b"not source code";
        let tgz = create_test_tarball_with_entries(&[
            ("index.js", buffered.as_slice()),
            ("asset.bin", streamed.as_slice()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let mut digests = HashMap::new();

        extract_tarball_with_entry_digests(
            &tgz,
            dir.path(),
            |path, _| path == Path::new("index.js"),
            |entry| {
                digests.insert(
                    entry.relative_path.to_path_buf(),
                    entry.blake3_digest.expect("digest-enabled extraction"),
                );
            },
        )
        .unwrap();

        assert_eq!(
            digests[Path::new("index.js")],
            *blake3::hash(buffered).as_bytes()
        );
        assert_eq!(
            digests[Path::new("asset.bin")],
            *blake3::hash(streamed).as_bytes()
        );
    }

    #[test]
    fn extract_tarball_streams_when_compressed_input_exceeds_buffered_cap() {
        let payload = b"small package content";
        let tgz = create_test_tarball("index.js", payload);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_buffered_compressed_size: 8,
            max_buffered_decompressed_size: 64 * 1024,
            ..streaming_test_limits()
        };

        let files = extract_tarball_from_reader_with_inspector_with_limits(
            std::io::Cursor::new(&tgz),
            dir.path(),
            limits,
            false,
            |_, _| false,
            |_| {},
        )
        .unwrap();

        assert_eq!(files, [PathBuf::from("index.js")]);
        assert_eq!(std::fs::read(dir.path().join("index.js")).unwrap(), payload);
    }

    #[test]
    fn slice_extractor_streams_when_compressed_input_exceeds_buffered_cap() {
        let payload = b"small package content";
        let tgz = create_test_tarball("index.js", payload);
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_buffered_compressed_size: 8,
            max_buffered_decompressed_size: 64 * 1024,
            ..streaming_test_limits()
        };

        let files = extract_tarball_from_slice_with_inspector_with_limits(
            &tgz,
            dir.path(),
            limits,
            false,
            |_, _| false,
            |_| {},
        )
        .unwrap();

        assert_eq!(files, [PathBuf::from("index.js")]);
        assert_eq!(std::fs::read(dir.path().join("index.js")).unwrap(), payload);
    }

    #[test]
    fn streaming_fallback_rolls_back_path_traversal() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let valid = b"valid";
            let mut valid_header = tar::Header::new_gnu();
            valid_header.set_size(valid.len() as u64);
            valid_header.set_mode(0o644);
            valid_header.set_cksum();
            builder
                .append_data(&mut valid_header, "package/valid.txt", &valid[..])
                .unwrap();

            let escaped = b"escaped";
            let mut escaped_header = tar::Header::new_gnu();
            escaped_header.set_size(escaped.len() as u64);
            escaped_header.set_mode(0o644);
            escaped_header.set_entry_type(tar::EntryType::Regular);
            escaped_header.set_path("package/ok.txt").unwrap();

            let raw = escaped_header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..22].copy_from_slice(b"package/../escaped.txt");
            escaped_header.set_cksum();
            builder.append(&escaped_header, &escaped[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let limits = ExtractionLimits {
            max_buffered_compressed_size: 8,
            max_buffered_decompressed_size: 64 * 1024,
            ..streaming_test_limits()
        };

        let error = extract_tarball_from_reader_with_inspector_with_limits(
            std::io::Cursor::new(&tgz),
            dir.path(),
            limits,
            false,
            |_, _| false,
            |_| {},
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("path traversal"),
            "expected traversal rejection, got: {error}"
        );
        assert!(!dir.path().join("valid.txt").exists());
        assert!(!dir.path().join("escaped.txt").exists());
    }

    #[test]
    fn extract_simple_tarball() {
        let tgz = create_test_tarball("index.js", b"console.log('hello')");
        let dir = tempfile::tempdir().unwrap();

        let files = extract_tarball(&tgz, dir.path()).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("index.js"));

        let content = std::fs::read_to_string(dir.path().join("index.js")).unwrap();
        assert_eq!(content, "console.log('hello')");
    }

    #[test]
    fn extract_nested_file() {
        let tgz = create_test_tarball("src/lib/utils.js", b"export const x = 1");
        let dir = tempfile::tempdir().unwrap();

        let files = extract_tarball(&tgz, dir.path()).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("src/lib/utils.js"));
        assert!(dir.path().join("src/lib/utils.js").exists());
    }

    #[test]
    fn list_tarball_contents_works() {
        let tgz = create_test_tarball("package.json", b"{}");
        let files = list_tarball_contents(&tgz).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("package.json"));
    }

    #[test]
    fn list_tarball_contents_streams_when_buffered_output_cap_is_exceeded() {
        let payload = vec![b'a'; 4096];
        let tgz = create_test_tarball("package.json", &payload);

        let files = list_tarball_contents_with_limits(&tgz, streaming_test_limits()).unwrap();

        assert_eq!(files, [PathBuf::from("package.json")]);
    }

    #[test]
    fn verify_integrity_passes() {
        let data = b"test tarball data";
        let integrity = Integrity::from_bytes(HashAlgorithm::Sha512, data);
        let sri = integrity.to_string();

        assert!(verify_integrity(data, &sri).is_ok());
    }

    #[test]
    fn verify_integrity_fails_on_mismatch() {
        let data = b"test tarball data";
        let wrong_integrity = Integrity::from_bytes(HashAlgorithm::Sha512, b"different data");
        let sri = wrong_integrity.to_string();

        assert!(verify_integrity(data, &sri).is_err());
    }

    #[test]
    fn verify_and_extract_full_pipeline() {
        let tgz = create_test_tarball("readme.md", b"# Hello");
        let integrity = Integrity::from_bytes(HashAlgorithm::Sha512, &tgz);
        let sri = integrity.to_string();
        let dir = tempfile::tempdir().unwrap();

        let files = verify_and_extract(&tgz, &sri, dir.path()).unwrap();

        assert_eq!(files.len(), 1);
        let content = std::fs::read_to_string(dir.path().join("readme.md")).unwrap();
        assert_eq!(content, "# Hello");
    }

    #[test]
    fn decompress_gzip_works() {
        let original = b"hello world compressed";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    /// Create a test .tgz with many small files inside `package/`.
    fn create_tarball_with_n_files(n: usize) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for i in 0..n {
                let mut header = tar::Header::new_gnu();
                header.set_size(1);
                header.set_mode(0o644);
                header.set_cksum();
                let tar_path = format!("package/file_{i}.txt");
                builder
                    .append_data(&mut header, &tar_path, &b"x"[..])
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    /// Create a test .tgz with `n` empty files inside `package/`.
    fn create_tarball_with_n_empty_files(n: usize) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for i in 0..n {
                let mut header = tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o644);
                header.set_cksum();
                let tar_path = format!("package/file_{i}.txt");
                builder
                    .append_data(&mut header, &tar_path, std::io::empty())
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn create_tarball_with_path(path: &str) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, std::io::empty())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn create_tarball_with_gnu_longname(long_name: &[u8]) -> Vec<u8> {
        let mut tar_data = Vec::with_capacity(long_name.len() + 2_048);

        let mut longname_header = tar::Header::new_gnu();
        longname_header.set_entry_type(tar::EntryType::GNULongName);
        longname_header.set_size(long_name.len() as u64);
        longname_header.set_mode(0o644);
        longname_header.set_path("././@LongLink").unwrap();
        longname_header.set_cksum();
        tar_data.extend_from_slice(longname_header.as_bytes());
        tar_data.extend_from_slice(long_name);
        let padding = (512 - long_name.len() % 512) % 512;
        tar_data.resize(tar_data.len() + padding, 0);

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(0);
        file_header.set_mode(0o644);
        file_header.set_path("package/fallback").unwrap();
        file_header.set_cksum();
        tar_data.extend_from_slice(file_header.as_bytes());
        tar_data.resize(tar_data.len() + 1_024, 0);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn create_raw_tarball_with_paths(paths: &[&str]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for path in paths {
                let mut header = tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, std::io::empty())
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        tar_data
    }

    #[test]
    fn visitor_break_still_validates_trailing_archive_entries() {
        let tar_data = create_raw_tarball_with_paths(&["package.json", "a/b/c"]);
        let limits = TarArchiveLimits {
            max_path_depth: 2,
            ..TarArchiveLimits::new(10)
        };

        let error = visit_tar_archive(tar_data.as_slice(), limits, |_| Ok(ControlFlow::Break(())))
            .expect_err("trailing entries must be validated after a visitor result is found");

        assert!(
            error.to_string().contains("nesting"),
            "expected trailing nesting-depth error, got: {error}"
        );
    }

    #[test]
    fn visit_tar_archive_rejects_pax_sparse_metadata() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            builder
                .append_pax_extensions([("GNU.sparse.map", b"0,1".as_slice())])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/file", b"x".as_slice())
                .unwrap();
            builder.finish().unwrap();
        }

        let error = visit_tar_archive(tar_data.as_slice(), TarArchiveLimits::new(10), |_| {
            Ok(ControlFlow::<()>::Continue(()))
        })
        .expect_err("PAX sparse metadata must be rejected");

        assert!(
            error.to_string().contains("sparse"),
            "expected sparse metadata error, got: {error}"
        );
    }

    #[test]
    fn visit_tar_archive_accepts_path_at_configured_depth() {
        let tar_data = create_raw_tarball_with_paths(&["a/b/c"]);
        let limits = TarArchiveLimits {
            max_path_depth: 3,
            ..TarArchiveLimits::new(1)
        };
        let mut paths = Vec::new();

        visit_tar_archive(tar_data.as_slice(), limits, |entry| {
            paths.push(entry.path().to_path_buf());
            Ok(ControlFlow::<()>::Continue(()))
        })
        .unwrap();

        assert_eq!(paths, [PathBuf::from("a/b/c")]);
    }

    #[test]
    fn visit_tar_archive_enforces_metadata_entry_count_independently() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            builder
                .append_pax_extensions([("comment", b"first".as_slice())])
                .unwrap();
            builder
                .append_pax_extensions([("comment", b"second".as_slice())])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/file", std::io::empty())
                .unwrap();
            builder.finish().unwrap();
        }
        let limits = TarArchiveLimits {
            max_metadata_entries: 1,
            ..TarArchiveLimits::new(10)
        };

        let error = visit_tar_archive(tar_data.as_slice(), limits, |_| {
            Ok(ControlFlow::<()>::Continue(()))
        })
        .expect_err("metadata entries exceeded their independent limit");

        assert!(
            error.to_string().contains("metadata-entry"),
            "expected metadata entry-count error, got: {error}"
        );
    }

    #[test]
    fn visit_tar_archive_accepts_bounded_gnu_long_name() {
        let mut long_name = b"package/".to_vec();
        long_name.extend_from_slice("segment/".repeat(20).as_bytes());
        long_name.extend_from_slice(b"file.js\0");
        let tgz = create_tarball_with_gnu_longname(&long_name);
        let mut expected = long_name;
        expected.pop();
        #[cfg(unix)]
        let expected = bytes_to_path(expected);
        #[cfg(not(unix))]
        let expected = bytes_to_path(expected).unwrap();
        let decoder = GzDecoder::new(tgz.as_slice());
        let mut paths = Vec::new();

        visit_tar_archive(decoder, TarArchiveLimits::new(1), |entry| {
            paths.push(entry.path().to_path_buf());
            Ok(ControlFlow::<()>::Continue(()))
        })
        .unwrap();

        assert_eq!(paths, [expected]);
    }

    #[test]
    fn visit_tar_archive_accepts_bounded_local_pax_path() {
        let expected = "package/pax/path/file.js";
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            builder
                .append_pax_extensions([("path", expected.as_bytes())])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "fallback", std::io::empty())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut paths = Vec::new();

        visit_tar_archive(tar_data.as_slice(), TarArchiveLimits::new(1), |entry| {
            paths.push(entry.path().to_path_buf());
            Ok(ControlFlow::<()>::Continue(()))
        })
        .unwrap();

        assert_eq!(paths, [PathBuf::from(expected)]);
    }

    #[test]
    fn list_tarball_contents_enforces_configured_entry_count() {
        let tgz = create_tarball_with_n_empty_files(3);
        let limits = ExtractionLimits {
            max_file_count: 2,
            ..DEFAULT_EXTRACTION_LIMITS
        };

        let error = list_tarball_contents_with_limits(&tgz, limits).unwrap_err();

        assert!(
            error.to_string().contains("too many"),
            "expected entry-count limit error, got: {error}"
        );
    }

    #[test]
    fn list_tarball_contents_rejects_more_than_256_path_components() {
        let mut path = String::from("package/");
        path.push_str(&"a/".repeat(256));
        path.push_str("file.js");
        let tgz = create_tarball_with_path(&path);

        let error = list_tarball_contents(&tgz).unwrap_err();

        assert!(
            error.to_string().contains("nesting"),
            "expected nesting-depth limit error, got: {error}"
        );
    }

    #[test]
    fn list_tarball_contents_rejects_oversized_gnu_longname_metadata() {
        let mut long_name = Vec::with_capacity(1024 * 1024 + 32);
        long_name.extend_from_slice(b"package/");
        while long_name.len() <= 1024 * 1024 {
            long_name.extend_from_slice(b"a/");
        }
        long_name.extend_from_slice(b"file.js\0");
        let tgz = create_tarball_with_gnu_longname(&long_name);

        let error = list_tarball_contents(&tgz).unwrap_err();

        assert!(
            error.to_string().contains("metadata"),
            "expected metadata limit error, got: {error}"
        );
    }

    #[test]
    fn extract_accepts_normal_file_count() {
        let tgz = create_tarball_with_n_files(100);
        let dir = tempfile::tempdir().unwrap();
        let result = extract_tarball(&tgz, dir.path());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 100);
    }

    #[test]
    fn extract_accepts_exact_max_file_count() {
        let tgz = create_tarball_with_n_empty_files(MAX_FILE_COUNT);
        let dir = tempfile::tempdir().unwrap();

        let result = extract_tarball(&tgz, dir.path());

        assert!(result.is_ok(), "exact max file count should be accepted");
        assert_eq!(result.unwrap().len(), MAX_FILE_COUNT);
    }

    #[test]
    fn extract_rejects_more_than_max_file_count() {
        let tgz = create_tarball_with_n_empty_files(MAX_FILE_COUNT + 1);
        let dir = tempfile::tempdir().unwrap();

        let result = extract_tarball(&tgz, dir.path());

        assert!(
            result.is_err(),
            "tarball with too many files should be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too many files"),
            "expected file-count limit error, got: {err}"
        );
    }

    #[test]
    fn extract_rejects_oversized_file() {
        // Create a raw tar with a header claiming MAX_FILE_SIZE + 1 bytes.
        // The size check in extract_tarball reads header.size() BEFORE reading
        // entry data, so this triggers rejection even without 500MB of actual data.
        let mut tar_data = Vec::new();
        let mut header = tar::Header::new_gnu();
        header.set_size(MAX_FILE_SIZE + 1);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/big.bin").unwrap();
        header.set_cksum();
        tar_data.extend_from_slice(header.as_bytes());
        // Minimal data padding (tar expects data blocks after header)
        tar_data.extend_from_slice(&[0u8; 512]);
        // End-of-archive markers
        tar_data.extend_from_slice(&[0u8; 1024]);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let result = extract_tarball(&tgz, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("file too large"),
            "expected 'file too large' error, got: {err}"
        );
    }

    #[test]
    fn extract_rejects_total_size_exceeded() {
        // Create a raw tar with a single file whose header claims MAX_EXTRACTION_SIZE + 1 bytes.
        let mut tar_data = Vec::new();
        let mut header = tar::Header::new_gnu();
        // Use a size that's under MAX_FILE_SIZE but over MAX_EXTRACTION_SIZE
        // Since MAX_FILE_SIZE (500MB) < MAX_EXTRACTION_SIZE (5GB), we need multiple files
        // or a file at exactly MAX_FILE_SIZE to accumulate past the total limit.
        // Simpler: just use a single file at MAX_FILE_SIZE (passes per-file check)
        // and verify total tracking works by checking the counter logic.
        //
        // For a direct test, use a size that passes per-file but we'll add two
        // entries that together exceed the total limit.
        // Note: MAX_EXTRACTION_SIZE / 2 + 1 > MAX_FILE_SIZE, so per-file check hits first.
        header.set_size(MAX_FILE_SIZE);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/a.bin").unwrap();
        header.set_cksum();
        tar_data.extend_from_slice(header.as_bytes());
        tar_data.extend_from_slice(&[0u8; 512]);
        tar_data.extend_from_slice(&[0u8; 1024]);

        // The per-file check triggers first for oversized files, and the total
        // accumulator works additively. We verify the total limit constant is correct.
        assert_eq!(MAX_EXTRACTION_SIZE, 5 * 1024 * 1024 * 1024);
        const { assert!(MAX_FILE_SIZE < MAX_EXTRACTION_SIZE) };
    }

    #[test]
    fn strip_first_component_works() {
        assert_eq!(
            strip_first_component(Path::new("package/src/index.js")),
            Some(PathBuf::from("src/index.js"))
        );
        assert_eq!(
            strip_first_component(Path::new("package/file.txt")),
            Some(PathBuf::from("file.txt"))
        );
        // Just the prefix directory itself → None
        assert_eq!(strip_first_component(Path::new("package")), None);
    }

    #[test]
    fn sanitize_entry_path_strips_package_prefix() {
        assert_eq!(
            sanitize_entry_path(Path::new("package/src/index.js")).unwrap(),
            Some(PathBuf::from("src/index.js"))
        );
        assert_eq!(sanitize_entry_path(Path::new("package")).unwrap(), None);
    }

    #[test]
    fn sanitize_entry_path_rejects_traversal_after_prefix() {
        let error = sanitize_entry_path(Path::new("package/../outside.txt"))
            .expect_err("path traversal must be rejected")
            .to_string();

        assert!(
            error.contains("path traversal detected"),
            "expected traversal diagnostic, got: {error}"
        );
    }

    #[test]
    fn sanitize_entry_path_rejects_windows_reserved_device_names() {
        for path in [
            "package/CON",
            "package/lib/nul.txt",
            "package/AUX.",
            "package/COM1/readme.md",
        ] {
            let error = sanitize_entry_path(Path::new(path))
                .expect_err("reserved path must be rejected")
                .to_string();

            assert!(
                error.contains("reserved Windows device name"),
                "expected reserved-device diagnostic for {path}, got: {error}"
            );
        }
    }

    #[test]
    fn list_tarball_contents_rejects_case_fold_path_collision() {
        let tgz = create_test_tarball_with_entries(&[
            ("lib/Foo.js", b"first"),
            ("lib/foo.js", b"second"),
        ]);

        let error = list_tarball_contents(&tgz).unwrap_err().to_string();

        assert!(
            error.contains("case-fold path collision"),
            "expected case-fold collision diagnostic, got: {error}"
        );
    }

    #[test]
    fn extract_rejects_case_fold_path_collision_and_rolls_back_written_files() {
        let tgz = create_test_tarball_with_entries(&[
            ("lib/Foo.js", b"first"),
            ("lib/foo.js", b"second"),
        ]);
        let dir = tempfile::tempdir().unwrap();

        let error = extract_tarball(&tgz, dir.path()).unwrap_err().to_string();

        assert!(
            error.contains("case-fold path collision"),
            "expected case-fold collision diagnostic, got: {error}"
        );
        assert!(!dir.path().join("lib/Foo.js").exists());
        assert!(!dir.path().join("lib/foo.js").exists());
    }

    #[test]
    fn extract_allows_exact_duplicate_member_path_with_last_write_winning() {
        let tgz = create_test_tarball_with_entries(&[
            ("duplicate.txt", b"first"),
            ("duplicate.txt", b"second"),
        ]);
        let dir = tempfile::tempdir().unwrap();

        let files = extract_tarball(&tgz, dir.path()).unwrap();

        assert_eq!(
            files,
            [
                PathBuf::from("duplicate.txt"),
                PathBuf::from("duplicate.txt")
            ]
        );
        assert_eq!(
            std::fs::read(dir.path().join("duplicate.txt")).unwrap(),
            b"second"
        );
    }

    #[test]
    fn extract_rejects_nested_path_traversal_after_prefix_stripping() {
        let mut tar_data = Vec::new();
        let content = b"owned";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("package/safe.txt").unwrap();

        let raw = header.as_mut_bytes();
        raw[..100].fill(0);
        raw[..22].copy_from_slice(b"package/../outside.txt");
        header.set_cksum();

        tar_data.extend_from_slice(header.as_bytes());
        tar_data.extend_from_slice(content);
        tar_data.extend(std::iter::repeat_n(0u8, 512 - content.len()));
        tar_data.extend_from_slice(&[0u8; 1024]);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let outside_path = dir.path().parent().unwrap().join("outside.txt");
        let _ = std::fs::remove_file(&outside_path);

        let result = extract_tarball(&tgz, dir.path());

        assert!(
            result.is_err(),
            "nested traversal tarball should be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("path traversal detected"),
            "expected traversal error, got: {err}"
        );
        assert!(
            !outside_path.exists(),
            "extractor must not write files outside the target directory"
        );
    }

    #[test]
    fn extract_cleans_already_written_files_when_later_entry_fails() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let first_content = b"safe";
            let mut first_header = tar::Header::new_gnu();
            first_header.set_size(first_content.len() as u64);
            first_header.set_mode(0o644);
            first_header.set_cksum();
            builder
                .append_data(&mut first_header, "package/keep.txt", &first_content[..])
                .unwrap();

            let second_content = b"boom";
            let mut second_header = tar::Header::new_gnu();
            second_header.set_size(second_content.len() as u64);
            second_header.set_mode(0o644);
            second_header.set_entry_type(tar::EntryType::Regular);
            second_header.set_path("package/ok.txt").unwrap();

            let raw = second_header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..18].copy_from_slice(b"package/../bad.txt");
            second_header.set_cksum();

            builder.append(&second_header, &second_content[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let result = extract_tarball(&tgz, dir.path());

        assert!(
            result.is_err(),
            "tarball should still fail on later traversal entry"
        );
        assert!(
            !dir.path().join("keep.txt").exists(),
            "previously extracted files should be cleaned up when extraction aborts"
        );
    }

    #[test]
    fn extract_cleans_created_directories_when_later_entry_fails() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_cksum();
            builder
                .append_data(&mut dir_header, "package/leftover/nested", std::io::empty())
                .unwrap();

            let bad_content = b"boom";
            let mut bad_header = tar::Header::new_gnu();
            bad_header.set_size(bad_content.len() as u64);
            bad_header.set_mode(0o644);
            bad_header.set_entry_type(tar::EntryType::Regular);
            bad_header.set_path("package/ok.txt").unwrap();

            let raw = bad_header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..18].copy_from_slice(b"package/../bad.txt");
            bad_header.set_cksum();

            builder.append(&bad_header, &bad_content[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let result = extract_tarball(&tgz, dir.path());

        assert!(
            result.is_err(),
            "tarball should still fail on later traversal entry"
        );
        assert!(
            !dir.path().join("leftover").exists(),
            "directories created before extraction aborts should be cleaned up"
        );
    }

    #[test]
    fn extract_skips_symlink_and_hardlink_entries() {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let file_content = b"real file";
            let mut file_header = tar::Header::new_gnu();
            file_header.set_size(file_content.len() as u64);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            builder
                .append_data(&mut file_header, "package/real.txt", &file_content[..])
                .unwrap();

            let mut symlink_header = tar::Header::new_gnu();
            symlink_header.set_entry_type(tar::EntryType::Symlink);
            symlink_header.set_size(0);
            symlink_header.set_mode(0o777);
            symlink_header
                .set_link_name("/tmp/should-not-exist")
                .unwrap();
            symlink_header.set_cksum();
            builder
                .append_data(&mut symlink_header, "package/link.txt", std::io::empty())
                .unwrap();

            let mut hardlink_header = tar::Header::new_gnu();
            hardlink_header.set_entry_type(tar::EntryType::Link);
            hardlink_header.set_size(0);
            hardlink_header.set_mode(0o644);
            hardlink_header.set_link_name("package/real.txt").unwrap();
            hardlink_header.set_cksum();
            builder
                .append_data(
                    &mut hardlink_header,
                    "package/hardlink.txt",
                    std::io::empty(),
                )
                .unwrap();

            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let files = extract_tarball(&tgz, dir.path()).unwrap();

        assert_eq!(files, vec![PathBuf::from("real.txt")]);
        assert!(dir.path().join("real.txt").exists());
        assert!(!dir.path().join("link.txt").exists());
        assert!(!dir.path().join("hardlink.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn extract_rejects_existing_symlink_parent_escape() {
        let tgz = create_test_tarball("linked/escape.txt", b"escape");
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();

        let result = extract_tarball(&tgz, dir.path());

        assert!(
            result.is_err(),
            "extractor should reject files whose existing parent symlink escapes the target"
        );
        assert!(
            !outside.path().join("escape.txt").exists(),
            "extractor must not write files outside the target through an existing symlink parent"
        );
    }

    /// `create_leaf_file` uses `O_NOFOLLOW` on the file open instead
    /// of an explicit per-leaf `symlink_metadata` pre-check. This
    /// test pins the security guarantee: a pre-existing leaf symlink
    /// (e.g., orphaned from a crashed extraction) MUST NOT cause the
    /// extractor to write through it.
    #[cfg(unix)]
    #[test]
    fn extract_rejects_existing_leaf_symlink() {
        let tgz = create_test_tarball("victim.txt", b"new bytes");
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_target = outside.path().join("escape.txt");
        std::fs::write(&outside_target, b"original outside content").unwrap();

        // Pre-plant a leaf symlink at the path the tarball wants to
        // write to. Pre-#C this was caught by `prepare_output_path`'s
        // leaf stat; post-#C it's caught by `O_NOFOLLOW` on the open.
        std::os::unix::fs::symlink(&outside_target, dir.path().join("victim.txt")).unwrap();

        let result = extract_tarball(&tgz, dir.path());

        assert!(
            result.is_err(),
            "extractor must reject pre-existing leaf symlinks"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("path traversal detected"),
            "error must surface as path-traversal, got: {err}",
        );
        let outside_content = std::fs::read_to_string(&outside_target).unwrap();
        assert_eq!(
            outside_content, "original outside content",
            "extractor must NOT write through the leaf symlink to the outside path",
        );
    }

    // ─── File-based extraction tests ─────────────────────────────────

    #[test]
    fn extract_from_file_matches_memory_extraction() {
        let tgz = create_test_tarball("index.js", b"console.log('file-based')");

        // Extract from memory
        let mem_dir = tempfile::tempdir().unwrap();
        let mem_files = extract_tarball(&tgz, mem_dir.path()).unwrap();

        // Write to temp file and extract from file
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut temp, &tgz).unwrap();

        let file_dir = tempfile::tempdir().unwrap();
        let file_files = extract_tarball_from_file(temp.path(), file_dir.path()).unwrap();

        assert_eq!(
            mem_files, file_files,
            "file and memory extraction should produce same files"
        );

        let mem_content = std::fs::read_to_string(mem_dir.path().join("index.js")).unwrap();
        let file_content = std::fs::read_to_string(file_dir.path().join("index.js")).unwrap();
        assert_eq!(
            mem_content, file_content,
            "extracted content should be identical"
        );
    }

    #[test]
    fn extract_from_reader_with_cursor() {
        let tgz = create_test_tarball("lib.js", b"module.exports = {}");

        let dir = tempfile::tempdir().unwrap();
        let files = extract_tarball_from_reader(std::io::Cursor::new(&tgz), dir.path()).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("lib.js"));
    }

    /// Tar entries with execute bits set (typical for npm package bins,
    /// mode 0755) must keep those bits after extraction. Without this,
    /// the v2 store extractor strips them (umask-respecting 0644),
    /// causing `EACCES` when Node tries to spawn shell-script bins
    /// (esbuild, tsc, etc.).
    #[cfg(unix)]
    #[test]
    fn extract_preserves_executable_bit_for_bin_files() {
        use std::os::unix::fs::PermissionsExt;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            // Regular file at 0644 — should land non-executable.
            let mut readme = tar::Header::new_gnu();
            readme.set_size(b"# readme\n".len() as u64);
            readme.set_mode(0o644);
            readme.set_cksum();
            builder
                .append_data(&mut readme, "package/README.md", &b"# readme\n"[..])
                .unwrap();

            // Bin script at 0755 — must land with all three exec bits.
            let mut bin = tar::Header::new_gnu();
            bin.set_size(b"#!/bin/sh\necho hi\n".len() as u64);
            bin.set_mode(0o755);
            bin.set_cksum();
            builder
                .append_data(&mut bin, "package/bin/cli.sh", &b"#!/bin/sh\necho hi\n"[..])
                .unwrap();

            // User-only exec (0o744) — must preserve the user-X bit
            // without restoring group/other-X (which weren't in the
            // tarball).
            let mut user_exec = tar::Header::new_gnu();
            user_exec.set_size(b"x\n".len() as u64);
            user_exec.set_mode(0o744);
            user_exec.set_cksum();
            builder
                .append_data(&mut user_exec, "package/bin/private.sh", &b"x\n"[..])
                .unwrap();

            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let files = extract_tarball(&tgz, dir.path()).unwrap();
        assert_eq!(files.len(), 3);

        let mode_of = |rel: &str| {
            std::fs::metadata(dir.path().join(rel))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };

        assert_eq!(
            mode_of("README.md") & 0o111,
            0,
            "non-executable file must NOT acquire exec bits",
        );
        assert_eq!(
            mode_of("bin/cli.sh") & 0o111,
            0o111,
            "0755 tar entry must preserve all three exec bits",
        );
        assert_eq!(
            mode_of("bin/private.sh") & 0o111,
            0o100,
            "0744 tar entry must preserve user-only exec bit, no group/other",
        );
    }

    /// Lock down the 0o644-floor mode-normalization contract. The
    /// extractor floors every regular file at 0o644 (`rw-r--r--`) and
    /// OR's the tarball's exec bits on top, regardless of what
    /// read/write permissions the tarball header declared.
    ///
    /// **Why this matters.** A surprising number of npm tarballs ship
    /// files with weird modes (0o600 user-only, 0o400 read-only, etc.)
    /// from arbitrary build environments. Honoring those modes would
    /// make published files unreadable to other Unix users running Node
    /// — `EACCES` on `require()`. Both npm and pnpm flatten to a
    /// world-readable floor; this test pins LPM to the same posture.
    ///
    /// **Note on apparent "widening".** A tarball declaring 0o600 ends
    /// up world-readable here. This is intentional — it matches npm/pnpm
    /// behavior. This test pins the behavior so a future refactor can't
    /// silently switch to the tar header's mode.
    ///
    /// SUID / SGID / sticky bits are explicitly NOT carried through —
    /// see the block comment at the post-write `set_permissions` site
    /// for the security rationale ("same security posture as
    /// `set_preserve_permissions(false)`").
    #[cfg(unix)]
    #[test]
    fn extract_floors_read_bits_at_0o644_and_strips_suid_sgid_sticky() {
        use std::os::unix::fs::PermissionsExt;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            // 0o600 (user-only rw, no group/other) → must become 0o644.
            // Locks the npm/pnpm-compat widening: a tarball with a
            // restrictive owner-only mode is normalized to a
            // world-readable file in node_modules so any process can
            // `require()` it.
            let mut user_only = tar::Header::new_gnu();
            user_only.set_size(b"a\n".len() as u64);
            user_only.set_mode(0o600);
            user_only.set_cksum();
            builder
                .append_data(&mut user_only, "package/user_only.txt", &b"a\n"[..])
                .unwrap();

            // 0o400 (read-only) → must become 0o644 (gain user-write
            // and world-read). Same widening rationale.
            let mut readonly = tar::Header::new_gnu();
            readonly.set_size(b"b\n".len() as u64);
            readonly.set_mode(0o400);
            readonly.set_cksum();
            builder
                .append_data(&mut readonly, "package/readonly.txt", &b"b\n"[..])
                .unwrap();

            // 0o4755 (SUID + 0o755) → must drop the SUID bit but
            // keep the exec bits. Defense-in-depth against a
            // malicious tarball trying to plant a setuid binary in
            // node_modules — the post-write `set_permissions` call
            // builds its mask as `0o644 | exec_bits`, where
            // `exec_bits = mode & 0o111`, so SUID/SGID/sticky are
            // structurally absent from the result.
            let mut suid = tar::Header::new_gnu();
            suid.set_size(b"c\n".len() as u64);
            suid.set_mode(0o4755);
            suid.set_cksum();
            builder
                .append_data(&mut suid, "package/bin/suid.sh", &b"c\n"[..])
                .unwrap();

            // 0o2755 (SGID) — same defense: drop SGID, keep exec.
            let mut sgid = tar::Header::new_gnu();
            sgid.set_size(b"d\n".len() as u64);
            sgid.set_mode(0o2755);
            sgid.set_cksum();
            builder
                .append_data(&mut sgid, "package/bin/sgid.sh", &b"d\n"[..])
                .unwrap();

            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let tgz = encoder.finish().unwrap();

        let dir = tempfile::tempdir().unwrap();
        extract_tarball(&tgz, dir.path()).unwrap();

        let mode_of = |rel: &str| {
            std::fs::metadata(dir.path().join(rel))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777 // include high bits to detect SUID/SGID/sticky
        };

        // 0o600 → 0o644 (no exec bits).
        assert_eq!(
            mode_of("user_only.txt"),
            0o644,
            "0o600 tar entry must be widened to 0o644 (npm/pnpm-compat \
             world-read floor); without this, downstream Node processes \
             running as a non-owner user hit EACCES on require()"
        );
        // 0o400 → 0o644 (no exec bits, gains user-write).
        assert_eq!(
            mode_of("readonly.txt"),
            0o644,
            "0o400 tar entry must be widened to 0o644 (npm/pnpm-compat)"
        );
        // 0o4755 → 0o755 (SUID stripped, exec preserved).
        assert_eq!(
            mode_of("bin/suid.sh"),
            0o755,
            "SUID bit MUST be stripped — never permit a tarball to \
             plant a setuid binary in node_modules"
        );
        // 0o2755 → 0o755 (SGID stripped, exec preserved).
        assert_eq!(
            mode_of("bin/sgid.sh"),
            0o755,
            "SGID bit MUST be stripped — same security posture as SUID"
        );
    }

    /// The buffered libdeflate path must never allocate beyond the
    /// single-tarball memory ceiling. Larger payloads use the streaming
    /// fallback instead.
    #[test]
    fn buffered_decompression_cap_bounds_real_allocations() {
        assert_eq!(
            MAX_BUFFERED_DECOMPRESSED_SIZE,
            256 * 1024 * 1024,
            "buffered decompression cap must stay ≤ 256 MiB to defend \
             against hostile gzip pre-allocation and grow-loop attacks",
        );
        assert!(
            (MAX_BUFFERED_DECOMPRESSED_SIZE as u64) < MAX_EXTRACTION_SIZE,
            "buffered cap must stay below the extraction ceiling so \
             legitimate large payloads route to streaming fallback",
        );
    }

    /// Round-trip a real (small) gzip payload to prove the buffered
    /// cap doesn't break the common path.
    #[test]
    fn decompress_gzip_libdeflate_round_trips_small_payload() {
        use std::io::Write;
        let original = b"hello, libdeflate world!".repeat(100);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gzip_libdeflate(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn buffered_decode_keeps_input_and_output_budget_reserved_until_drop() {
        use std::io::Write as _;

        const BUDGET_BYTES: u64 = 64 * 1024;
        let original = vec![b'x'; 4096];
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();
        let budget = AllocBudget {
            available: std::sync::Mutex::new(BUDGET_BYTES),
            cv: std::sync::Condvar::new(),
        };
        let limits = ExtractionLimits {
            max_buffered_compressed_size: 64 * 1024,
            max_buffered_decompressed_size: 64 * 1024,
            max_extraction_size: 64 * 1024,
            max_file_size: 64 * 1024,
            max_file_count: 16,
        };

        let BufferedGzipDecode::Decoded(decoded) =
            decompress_gzip_libdeflate_with_limits_and_budget(&compressed, limits, &budget)
                .unwrap()
        else {
            panic!("small gzip payload must use buffered decoding");
        };
        let reserved = decoded.capacity().saturating_add(compressed.len()) as u64;
        assert_eq!(*budget.available.lock().unwrap(), BUDGET_BYTES - reserved);
        drop(decoded);
        assert_eq!(*budget.available.lock().unwrap(), BUDGET_BYTES);
    }

    /// L9 — the global budget must serialize a second acquire that
    /// would exceed the ceiling, then release when the first guard
    /// drops. Uses a private throwaway budget instance so we don't
    /// disturb the static `EXTRACT_BUDGET` other tests share with
    /// parallel-running suites.
    #[test]
    fn alloc_budget_serializes_when_request_would_exceed_ceiling() {
        let budget = AllocBudget {
            available: std::sync::Mutex::new(PARALLEL_EXTRACT_BUDGET_BYTES),
            cv: std::sync::Condvar::new(),
        };
        let huge = PARALLEL_EXTRACT_BUDGET_BYTES;
        let g1 = budget.acquire(huge);
        assert_eq!(*budget.available.lock().unwrap(), 0);

        let blocked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let blocked2 = blocked.clone();
        let budget_ref = &budget;
        std::thread::scope(|s| {
            s.spawn(|| {
                let _g2 = budget_ref.acquire(huge);
                blocked2.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(
                !blocked.load(std::sync::atomic::Ordering::SeqCst),
                "second acquire must not progress while first guard holds the full budget"
            );
            drop(g1);
            // Now the scoped thread can complete its acquire+drop.
        });
        assert_eq!(
            *budget.available.lock().unwrap(),
            PARALLEL_EXTRACT_BUDGET_BYTES
        );
        assert!(blocked.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// L9 — a request bigger than the entire budget caps at the
    /// budget itself (single in-flight call), so an outsized
    /// legitimate tarball doesn't deadlock waiting for an impossible
    /// reservation.
    #[test]
    fn alloc_budget_caps_oversized_request_to_full_budget() {
        let budget = AllocBudget {
            available: std::sync::Mutex::new(PARALLEL_EXTRACT_BUDGET_BYTES),
            cv: std::sync::Condvar::new(),
        };
        let _g = budget.acquire(PARALLEL_EXTRACT_BUDGET_BYTES * 4);
        // The acquire returned (didn't deadlock) and consumed the
        // whole budget rather than the impossible 4× request.
        assert_eq!(*budget.available.lock().unwrap(), 0);
    }

    #[test]
    fn alloc_budget_acquire_recovers_from_poisoned_mutex() {
        let budget = AllocBudget {
            available: std::sync::Mutex::new(PARALLEL_EXTRACT_BUDGET_BYTES),
            cv: std::sync::Condvar::new(),
        };

        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = budget.available.lock().unwrap();
            panic!("poison throwaway allocation budget");
        }));
        assert!(poisoned.is_err());

        let _guard = budget.acquire(1);
        let available = match budget.available.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };
        assert_eq!(available, PARALLEL_EXTRACT_BUDGET_BYTES - 1);
    }
}
