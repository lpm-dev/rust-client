use std::path::PathBuf;

use lpm_common::LpmError;
use sha1::Sha1;
use sha2::{Digest, Sha512};

use crate::{PackageStore, StageTimings, compute_sri_hash, is_complete_package_dir};

impl PackageStore {
    /// Extract a tarball into the store. Returns the store path.
    ///
    /// If the package already exists in the store, skips extraction (cache hit).
    ///
    /// Uses a unique temp directory per process+thread to prevent TOCTOU races
    /// when multiple parallel downloads extract the same package simultaneously.
    /// The final rename is atomic on the same filesystem — if another thread wins
    /// the race, we discard our work and use theirs.
    pub fn store_package(
        &self,
        name: &str,
        version: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        let dir = self.package_dir(name, version);
        let label = format!("{name}@{version}");
        self.store_at_dir(dir, &label, tarball_data)
    }

    /// Shared inner extraction logic used by [`Self::store_package`]
    /// and [`Self::store_tarball_at_cas_path`].
    ///
    /// `dir` is the destination directory (different per-source-kind).
    /// `label` is a human-readable identifier for tracing/error
    /// messages; carries `name@version` for Registry sources or a
    /// truncated SRI for Tarball sources.
    pub(crate) fn store_at_dir(
        &self,
        dir: PathBuf,
        label: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        // Fast path: already stored
        if dir.exists() {
            if is_complete_package_dir(&dir) {
                self.backfill_security_cache_if_enabled(&dir, label);
                tracing::debug!("store hit: {label}");
                return Ok(dir);
            }

            std::fs::remove_dir_all(&dir).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove incomplete store entry for {label}: {e}"
                ))
            })?;
        }

        tracing::debug!("extracting {label} to store");

        // Use a unique temp dir to prevent races between parallel downloads.
        // Each process+thread gets its own temp directory so concurrent extractions
        // never step on each other.
        let unique_id = std::process::id();
        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = dir.with_extension(format!("tmp.{unique_id}.{thread_id}"));

        // Clean up any stale tmp dir from a previous crash
        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }

        // Ensure parent directory exists
        if let Some(parent) = tmp_dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LpmError::Store(format!("failed to create store dir: {e}")))?;
        }

        if let Err(error) = lpm_extractor::extract_tarball(tarball_data, &tmp_dir) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(error);
        }

        // Write SRI integrity hash of the original tarball. This
        // records the tarball-time digest only — `store verify --deep`
        // uses it for lockfile↔marker consistency (the marker matches
        // the lockfile's claimed integrity). It does NOT re-hash the
        // extracted on-disk bytes, so a post-extraction tamper that
        // leaves the `.integrity` marker untouched goes undetected. A
        // byte-integrity recompute would need a Merkle digest of the
        // extracted directory + a place to store it; not implemented.
        let sri = compute_sri_hash(tarball_data);
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), &sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!("failed to write .integrity: {e}")));
        }

        // Run behavioral security analysis and write .lpm-security.json.
        // Done BEFORE the atomic rename so the analysis result is included
        // atomically — when the package dir becomes visible, the security
        // cache is already present. Analysis failure is non-fatal (warn only).
        if self.security_analysis_policy().is_enabled() {
            let analysis = lpm_security::behavioral::analyze_package(&tmp_dir);
            if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
                tracing::warn!("failed to write .lpm-security.json for {label}: {e}");
            } else {
                tracing::debug!(
                    "security analysis: {label} — {} files scanned, {} bytes",
                    analysis.meta.files_scanned,
                    analysis.meta.bytes_scanned
                );
            }
        }

        // Atomic rename — if another thread already completed, rename fails (that's OK)
        match std::fs::rename(&tmp_dir, &dir) {
            Ok(()) => Ok(dir),
            Err(_) if dir.exists() => {
                // Another thread/process beat us — clean up our temp dir and use theirs
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Ok(dir)
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!("failed to store package: {e}")))
            }
        }
    }

    /// Extract a tarball from a file into the store. Returns the store path.
    ///
    /// Bounded-memory variant of `store_package()` — reads the tarball from disk
    /// in chunks rather than requiring it in memory. The SRI hash is provided by
    /// the caller (computed during download).
    ///
    /// Same atomicity guarantees as `store_package()`: unique temp dir per
    /// process+thread, atomic rename into final location.
    ///
    /// Timing-agnostic wrapper around [`PackageStore::store_package_from_file_timed`].
    /// Prefer the timed variant on the install hot path so `lpm install --json`
    /// can surface a proper fetch-stage breakdown.
    pub fn store_package_from_file(
        &self,
        name: &str,
        version: &str,
        tarball_path: &std::path::Path,
        sri: &str,
    ) -> Result<PathBuf, LpmError> {
        self.store_package_from_file_timed(name, version, tarball_path, sri)
            .map(|(path, _)| path)
    }

    /// Streaming path: hash + decompress + extract + scan + rename,
    /// all in one pass, no temp file.
    ///
    /// The caller pipes a tarball byte stream into `reader` (typically a
    /// [`tokio::io::SyncIoBridge`] over a [`tokio_util::io::StreamReader`]
    /// built from `reqwest::Response::bytes_stream()`). This method runs
    /// synchronously inside a `spawn_blocking` task because gzip decode +
    /// `tar::Archive` are sync and CPU-bound.
    ///
    /// ## Pipeline
    /// ```text
    /// reader  ──►  SizeLimitedReader  ──►  HashingReader  ──►  extractor
    ///           (500 MB ceiling)        (SHA-512 tee)        (libdeflate buffer
    ///                                                         with GzDecoder
    ///                                                         fallback)
    ///                                                                │
    ///                                                                ▼
    ///                                              tar::Archive ──► staging dir
    /// ```
    ///
    /// ## Integrity contract
    /// The SHA-512 hash is computed on the raw compressed bytes as they
    /// flow through — same byte domain the existing
    /// `download_tarball_to_file` path uses. If `expected_integrity` is
    /// `Some`, the computed SRI string is compared post-extract:
    /// - Match → atomic rename into the visible store path.
    /// - Mismatch → staging dir is removed, returns `LpmError::Registry`.
    ///
    /// Unlike `store_package_from_file_timed`, this path does NOT support
    /// non-sha512 expected-integrity algorithms (e.g. sha256) — we've
    /// consumed the stream by the time we'd need to re-hash. Callers
    /// that receive non-sha512 integrity from the registry must use the
    /// legacy `download_tarball_to_file` + `store_package_from_file_timed`
    /// path (currently all LPM registry packages publish sha512 SRIs).
    ///
    /// ## Failure semantics
    /// Any error after staging-dir creation cleans up the staging dir
    /// before returning. Same atomic rename fallback as the legacy paths:
    /// a concurrent winner is accepted silently.
    ///
    /// Returns `(store_path, computed_sri, timings)` where `timings`
    /// measures the in-blocking-thread portion only — `download_ms` and
    /// `queue_wait_ms` are owned by the async caller.
    pub fn stream_and_store_package(
        &self,
        name: &str,
        version: &str,
        reader: impl std::io::Read,
        expected_integrity: Option<&str>,
        max_compressed_size: u64,
    ) -> Result<(PathBuf, String, StageTimings), LpmError> {
        let dir = self.package_dir(name, version);
        let mut timings = StageTimings::default();

        // Fast path: already stored.
        if dir.exists() {
            if is_complete_package_dir(&dir) {
                self.backfill_security_cache_if_enabled(&dir, &format!("{name}@{version}"));
                tracing::debug!("store hit: {name}@{version}");
                // We didn't actually touch the stream — caller must have
                // pre-checked via `has_package()` to avoid wasted network.
                // Return the existing on-disk SRI so the caller can still
                // write a lockfile.
                let sri = std::fs::read_to_string(dir.join(".integrity"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                return Ok((dir, sri, timings));
            }
            std::fs::remove_dir_all(&dir).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove incomplete store entry for {name}@{version}: {e}"
                ))
            })?;
        }

        tracing::debug!("streaming {name}@{version} into store");

        let unique_id = std::process::id();
        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = dir.with_extension(format!("tmp.{unique_id}.{thread_id}"));

        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }

        if let Some(parent) = tmp_dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LpmError::Store(format!("failed to create store dir: {e}")))?;
        }

        // Extract timer covers: hashing + size-limit + gzip-decode + tar-walk
        // + write-to-staging + inline security scan. This is the combined
        // cost of what the legacy path splits across "download to temp" +
        // "reopen + extract" + "walk extracted tree". With streaming extraction these stages
        // collapse into a single filesystem pass — the extractor hands each
        // scannable entry's bytes to the analyzer while still holding them
        // in the write buffer.
        let extract_start = std::time::Instant::now();
        let size_limited = SizeLimitedReader::new(reader, max_compressed_size);
        let mut hashing_reader = HashingReader::new(size_limited);

        // Defense-in-depth pre-flight: verify the bytes start with
        // the gzip magic (0x1F 0x8B) BEFORE the rest of the stream
        // gets fed to the extractor and behavioral analyzer. The full
        // integrity verification still happens after extraction (the
        // streaming design fundamentally requires it), but a non-gzip
        // body — for example raw HTML from a misconfigured registry
        // or a hostile non-tarball response — now fails fast instead
        // of running the entire extractor + analyzer path on
        // attacker-chosen bytes. The 2 prefix bytes are hashed via
        // the `HashingReader::read_exact` path so the final SRI still
        // covers the full stream; they're then re-emitted into the
        // extractor via a `Chain` so the extractor's gzip decoder
        // sees a complete stream.
        let mut magic = [0u8; 2];
        if let Err(e) = std::io::Read::read_exact(&mut hashing_reader, &mut magic) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            let _ = hashing_reader.finalize();
            return Err(LpmError::Io(e));
        }
        if magic != [0x1F, 0x8B] {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            let _ = hashing_reader.finalize();
            return Err(LpmError::Registry(format!(
                "package body for {name}@{version} is not a gzip stream (first bytes: {:02x} {:02x}); refusing to extract",
                magic[0], magic[1],
            )));
        }
        let extractor_reader =
            std::io::Read::chain(std::io::Cursor::new(magic), &mut hashing_reader);

        // Fused behavioral scan. The predicate buffers JS/TS/JSX/TSX
        // sources that are small enough for the full scanner. Oversized
        // source files stream to disk first, then the inspector asks the
        // analyzer to read bounded head/tail samples from the written file.
        // Non-source files stream through unchanged.
        let source_analysis_enabled = self.security_analysis_policy().is_enabled();
        let analyzer = std::cell::RefCell::new(lpm_security::behavioral::PackageAnalyzer::new());

        // `&mut HashingReader` satisfies `impl Read` via the blanket impl
        // `impl<R: Read> Read for &mut R`, so we retain ownership and can
        // call `finalize` after extraction completes. Extractor errors
        // (including `SizeLimitedReader` tripping its cap via `Read` returning
        // an error) propagate through here unchanged.
        let extract_result = lpm_extractor::extract_tarball_from_reader_with_inspector(
            extractor_reader,
            &tmp_dir,
            |path, size| {
                source_analysis_enabled
                    && lpm_security::behavioral::PackageAnalyzer::should_buffer_source(path, size)
            },
            |entry| {
                if !source_analysis_enabled {
                    return;
                }
                if let Some(bytes) = entry.bytes {
                    analyzer.borrow_mut().feed(entry.relative_path, bytes);
                } else {
                    analyzer.borrow_mut().feed_oversized_source_file(
                        entry.relative_path,
                        &tmp_dir.join(entry.relative_path),
                        entry.size,
                    );
                }
            },
        );

        if let Err(error) = extract_result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            let _ = hashing_reader.finalize(); // discard partial hash
            return Err(error);
        }

        // Critical for SRI correctness: drain any raw compressed bytes the
        // extractor did not need to pull. The buffered libdeflate path usually
        // drains the stream before the tar walk; the streaming fallback can
        // stop after the gzip member, leaving trailing bytes for this final
        // hash pass. `io::sink()` discards the bytes; the hasher update inside
        // `HashingReader::read` still fires on every byte.
        if let Err(e) = std::io::copy(&mut hashing_reader, &mut std::io::sink()) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            let _ = hashing_reader.finalize();
            return Err(LpmError::Io(e));
        }

        let (computed_sri, computed_sha256, computed_sha1, _compressed_size) =
            hashing_reader.finalize();
        timings.extract_ms = extract_start.elapsed().as_millis();

        // Verify against the algorithm declared in `expected`. A
        // non-sha512 expected value must be checked against the matching
        // digest instead of being silently compared to sha512.
        //
        // Use constant-time `ct_eq` instead of `!=` so a future
        // attacker-influenced caller (server-side verifier, observable
        // timing channel) doesn't see per-byte digest information leak
        // through `String::eq`'s early exit.
        if let Some(expected) = expected_integrity {
            use subtle::ConstantTimeEq;
            let candidate = if expected.starts_with("sha512-") {
                &computed_sri
            } else if expected.starts_with("sha256-") {
                &computed_sha256
            } else if expected.starts_with("sha1-") {
                &computed_sha1
            } else {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(LpmError::Registry(format!(
                    "unsupported integrity algorithm for {name}@{version}: {expected} — \
                     expected sha512-… (preferred), sha256-…, or sha1-…"
                )));
            };
            let matches_expected = expected.len() == candidate.len()
                && expected.as_bytes().ct_eq(candidate.as_bytes()).into();
            if !matches_expected {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(LpmError::Registry(format!(
                    "integrity mismatch for {name}@{version}: expected {expected}, got {candidate}"
                )));
            }
        }

        // Security analysis was fused into the tar walk above. What
        // remains is finalize — read `package.json` from staging (one
        // file open, always present in npm tarballs), run manifest-
        // level tag analysis, merge dedup'd URL domains, compute the
        // package-level `trivial` tag, and serialize to
        // `.lpm-security.json`. Per-source-file bytes are not re-read.
        if source_analysis_enabled {
            let security_start = std::time::Instant::now();
            let analyzer = analyzer.into_inner();
            timings.source_scan_ns = analyzer.source_scan_ns();
            let analysis = analyzer.finalize(&tmp_dir);
            if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
                tracing::warn!("failed to write .lpm-security.json for {name}@{version}: {e}");
            }
            timings.security_ms = security_start.elapsed().as_millis();
        }

        // Finalize: write integrity, atomic rename.
        let finalize_start = std::time::Instant::now();
        let integrity_write_start = std::time::Instant::now();
        let integrity_result = std::fs::write(tmp_dir.join(".integrity"), &computed_sri);
        timings.finalize_integrity_write_ms = integrity_write_start.elapsed().as_millis();
        if let Err(e) = integrity_result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!("failed to write .integrity: {e}")));
        }
        let rename_start = std::time::Instant::now();
        let rename_result = std::fs::rename(&tmp_dir, &dir);
        timings.finalize_rename_ms = rename_start.elapsed().as_millis();
        timings.finalize_ms = finalize_start.elapsed().as_millis();

        match rename_result {
            Ok(()) => Ok((dir, computed_sri, timings)),
            Err(_) if dir.exists() => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Ok((dir, computed_sri, timings))
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!("failed to store package: {e}")))
            }
        }
    }

    /// Same contract as [`PackageStore::store_package_from_file`], plus a
    /// [`StageTimings`] breakdown (extract / security / finalize) for the
    /// caller. On the store-hit fast path every field is zero.
    ///
    /// `extract_ms` covers `extract_tarball_from_file`; when analysis is
    /// enabled, `security_ms` covers `analyze_package` plus the cache write;
    /// `finalize_ms` covers the `.integrity` file write plus the atomic rename.
    /// The sum of the three is the wall-clock of the miss path excluding the
    /// initial `dir.exists()` stat.
    pub fn store_package_from_file_timed(
        &self,
        name: &str,
        version: &str,
        tarball_path: &std::path::Path,
        sri: &str,
    ) -> Result<(PathBuf, StageTimings), LpmError> {
        let dir = self.package_dir(name, version);
        let mut timings = StageTimings::default();

        // Fast path: already stored. Callers on the install hot path pre-filter
        // against `has_package()` so this should never hit; we keep it for the
        // general-purpose API contract.
        if dir.exists() {
            if is_complete_package_dir(&dir) {
                self.backfill_security_cache_if_enabled(&dir, &format!("{name}@{version}"));
                tracing::debug!("store hit: {name}@{version}");
                return Ok((dir, timings));
            }

            std::fs::remove_dir_all(&dir).map_err(|e| {
                LpmError::Store(format!(
                    "failed to remove incomplete store entry for {name}@{version}: {e}"
                ))
            })?;
        }

        tracing::debug!("extracting {name}@{version} to store (from file)");

        let unique_id = std::process::id();
        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = dir.with_extension(format!("tmp.{unique_id}.{thread_id}"));

        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }

        if let Some(parent) = tmp_dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LpmError::Store(format!("failed to create store dir: {e}")))?;
        }

        // Extract from file — bounded memory, no full tarball in heap
        let extract_start = std::time::Instant::now();
        if let Err(error) = lpm_extractor::extract_tarball_from_file(tarball_path, &tmp_dir) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(error);
        }
        timings.extract_ms = extract_start.elapsed().as_millis();

        // Write pre-computed SRI hash (no second pass needed). Runs
        // before the security scan to keep the original execution
        // order. Counted under `finalize_ms` because it's cheap
        // housekeeping, not a sub-stage we expect to optimize.
        let finalize_start = std::time::Instant::now();
        let integrity_result = std::fs::write(tmp_dir.join(".integrity"), sri);
        timings.finalize_integrity_write_ms = finalize_start.elapsed().as_millis();
        if let Err(e) = integrity_result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!("failed to write .integrity: {e}")));
        }

        // When enabled, security analysis runs on the extracted tree before
        // the atomic rename so the cache is published with the package.
        // Measured separately from finalize to expose the second-filesystem-
        // pass cost that the fused stream path eliminates.
        if self.security_analysis_policy().is_enabled() {
            let security_start = std::time::Instant::now();
            let (analysis, analysis_timings) =
                lpm_security::behavioral::analyze_package_with_timings(&tmp_dir);
            timings.source_scan_ns = analysis_timings.source_scan_ns;
            if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
                tracing::warn!("failed to write .lpm-security.json for {name}@{version}: {e}");
            } else {
                tracing::debug!(
                    "security analysis: {name}@{version} — {} files scanned, {} bytes",
                    analysis.meta.files_scanned,
                    analysis.meta.bytes_scanned
                );
            }
            timings.security_ms = security_start.elapsed().as_millis();
        }

        // Finalize: atomic rename into the visible path.
        let rename_start = std::time::Instant::now();
        let rename_result = std::fs::rename(&tmp_dir, &dir);
        timings.finalize_rename_ms = rename_start.elapsed().as_millis();
        timings.finalize_ms = timings.finalize_integrity_write_ms + timings.finalize_rename_ms;

        match rename_result {
            Ok(()) => Ok((dir, timings)),
            Err(_) if dir.exists() => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Ok((dir, timings))
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                Err(LpmError::Store(format!("failed to store package: {e}")))
            }
        }
    }
}

/// Transparent `Read` wrapper that feeds every byte into BOTH a
/// SHA-512 and a SHA-256 hasher as it flows through. Computes the
/// tarball SRI inline with streaming extraction — no second pass, no
/// temp file.
///
/// SHA-512 is canonical; SHA-256 is computed in parallel because
/// some legitimate npm lockfile entries still ship `sha256-…` SRI
/// (older publishes / mirrors). The verifier compares against whichever computed digest
/// matches the expected algorithm, so a sha256 expected value
/// actually gets verified against the matching computation.
///
/// After the extractor finishes consuming the stream, call
/// [`HashingReader::finalize`] to obtain `(sha512_sri, sha256_sri, sha1_sri, total_bytes)`.
struct HashingReader<R> {
    inner: R,
    sha512: Sha512,
    sha256: sha2::Sha256,
    sha1: Sha1,
    bytes: u64,
}

impl<R: std::io::Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        use sha2::Digest;
        Self {
            inner,
            sha512: Sha512::new(),
            sha256: sha2::Sha256::new(),
            sha1: Sha1::new(),
            bytes: 0,
        }
    }

    /// Finalize all hashers and return `(sha512_sri, sha256_sri, sha1_sri, total_bytes)`.
    /// Consumes `self` because the hashers are one-shot.
    fn finalize(self) -> (String, String, String, u64) {
        use base64::Engine;
        let sha512_digest = self.sha512.finalize();
        let sha256_digest = self.sha256.finalize();
        let sha1_digest = self.sha1.finalize();
        let sha512_sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha512_digest)
        );
        let sha256_sri = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(sha256_digest)
        );
        let sha1_sri = format!(
            "sha1-{}",
            base64::engine::general_purpose::STANDARD.encode(sha1_digest)
        );
        (sha512_sri, sha256_sri, sha1_sri, self.bytes)
    }
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.sha512.update(&buf[..n]);
            self.sha256.update(&buf[..n]);
            self.sha1.update(&buf[..n]);
            self.bytes += n as u64;
        }
        Ok(n)
    }
}

/// Caps total bytes read to `limit`. Tripping the limit returns
/// `ErrorKind::InvalidData` with a message mirroring the
/// `download_tarball_to_file` rejection, surfacing through the
/// extractor as `LpmError::Io`. No bytes past the cap are ever
/// written to the staging directory.
struct SizeLimitedReader<R> {
    inner: R,
    bytes_read: u64,
    limit: u64,
}

impl<R: std::io::Read> SizeLimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            bytes_read: 0,
            limit,
        }
    }
}

impl<R: std::io::Read> std::io::Read for SizeLimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Clamp the read length so we never exceed `limit` in a single
        // syscall — and trip the error on the read that would cross it.
        let remaining = self.limit.saturating_sub(self.bytes_read);
        if remaining == 0 {
            // Peek one byte to distinguish clean EOF from over-limit.
            let mut scratch = [0u8; 1];
            return match self.inner.read(&mut scratch)? {
                0 => Ok(0),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "tarball exceeds maximum compressed size ({} bytes limit)",
                        self.limit
                    ),
                )),
            };
        }
        let max = std::cmp::min(buf.len() as u64, remaining) as usize;
        let n = self.inner.read(&mut buf[..max])?;
        self.bytes_read += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::create_test_tarball;
    use crate::{compute_sri_hash_sha1, compute_sri_hash_sha256, read_stored_integrity};

    #[test]
    fn store_and_retrieve_package() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"foo\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 42"),
        ]);

        assert!(!store.has_package("foo", "1.0.0"));

        let path = store.store_package("foo", "1.0.0", &tarball).unwrap();
        assert!(store.has_package("foo", "1.0.0"));
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());
    }

    #[test]
    fn store_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);

        store.store_package("bar", "2.0.0", &tarball).unwrap();
        let path = store.store_package("bar", "2.0.0", &tarball).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn incomplete_cached_package_is_repaired_instead_of_treated_as_store_hit() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let package_dir = store.package_dir("repair-me", "1.0.0");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(package_dir.join("package.json"), b"{}").unwrap();

        let tarball = create_test_tarball(&[
            ("package.json", br#"{"name":"repair-me","version":"1.0.0"}"#),
            ("index.js", b"module.exports = 'repaired'"),
        ]);

        let path = store.store_package("repair-me", "1.0.0", &tarball).unwrap();

        assert!(
            path.join("index.js").exists(),
            "store should repair incomplete cached package"
        );
        assert!(
            path.join(".integrity").exists(),
            "repaired package should have integrity metadata"
        );
    }

    #[test]
    fn scoped_package_name_safe_on_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);

        let path = store
            .store_package("@types/node", "22.0.0", &tarball)
            .unwrap();
        assert!(path.exists());
        let dir_name = path.file_name().unwrap().to_string_lossy();
        assert!(!dir_name.contains('/'));
    }

    #[test]
    fn store_same_package_twice_returns_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball =
            create_test_tarball(&[("package.json", b"{\"name\":\"dup\",\"version\":\"1.0.0\"}")]);

        let path1 = store.store_package("dup", "1.0.0", &tarball).unwrap();
        assert!(path1.exists());

        let path2 = store.store_package("dup", "1.0.0", &tarball).unwrap();
        assert_eq!(path1, path2);
        assert!(path2.join("package.json").exists());
    }

    #[test]
    fn store_different_packages_no_interference() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball_a = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"pkg-a\",\"version\":\"1.0.0\"}",
        )]);
        let tarball_b = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"pkg-b\",\"version\":\"2.0.0\"}",
        )]);

        let path_a = store.store_package("pkg-a", "1.0.0", &tarball_a).unwrap();
        let path_b = store.store_package("pkg-b", "2.0.0", &tarball_b).unwrap();

        assert_ne!(path_a, path_b);
        assert!(path_a.join("package.json").exists());
        assert!(path_b.join("package.json").exists());
    }

    #[test]
    fn store_writes_integrity_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"integ\",\"version\":\"1.0.0\"}",
        )]);

        let path = store.store_package("integ", "1.0.0", &tarball).unwrap();
        let integrity_path = path.join(".integrity");
        assert!(integrity_path.exists(), ".integrity file must be written");

        let stored = std::fs::read_to_string(&integrity_path).unwrap();
        assert!(
            stored.starts_with("sha512-"),
            "integrity must be SRI format"
        );
        assert_eq!(stored, compute_sri_hash(&tarball));
    }

    #[test]
    fn store_writes_security_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"sec-test\",\"version\":\"1.0.0\",\"license\":\"MIT\"}",
            ),
            ("index.js", b"const fs = require('fs'); eval('code')"),
        ]);

        let path = store.store_package("sec-test", "1.0.0", &tarball).unwrap();
        let security_path = path.join(".lpm-security.json");
        assert!(
            security_path.exists(),
            ".lpm-security.json must be written during extraction"
        );

        let content = std::fs::read_to_string(&security_path).unwrap();
        let analysis: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(
            analysis["version"],
            lpm_security::behavioral::SCHEMA_VERSION
        );
        assert_eq!(analysis["source"]["filesystem"], true);
        assert_eq!(analysis["source"]["eval"], true);
        assert_eq!(analysis["source"]["network"], false);
        assert_eq!(analysis["manifest"]["copyleftLicense"], false);
        assert_eq!(analysis["manifest"]["noLicense"], false);
    }

    #[test]
    fn disabled_source_analysis_skips_fresh_v1_cache_creation() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at_with_security_analysis_policy(
            dir.path(),
            crate::SecurityAnalysisPolicy::Disabled,
        );
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"unscanned\",\"version\":\"1.0.0\"}",
            ),
            ("index.js", b"eval('code')"),
        ]);

        let path = store.store_package("unscanned", "1.0.0", &tarball).unwrap();

        assert!(!path.join(".lpm-security.json").exists());
        assert!(path.join(".integrity").exists());
    }

    #[test]
    fn enabled_v1_cache_hit_backfills_missing_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let disabled = PackageStore::at_with_security_analysis_policy(
            dir.path(),
            crate::SecurityAnalysisPolicy::Disabled,
        );
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"backfill\",\"version\":\"1.0.0\"}",
            ),
            ("index.js", b"eval('code')"),
        ]);
        let path = disabled
            .store_package("backfill", "1.0.0", &tarball)
            .unwrap();
        assert!(!path.join(".lpm-security.json").exists());

        let enabled = PackageStore::at(dir.path());
        assert!(enabled.has_package("backfill", "1.0.0"));

        let analysis = lpm_security::behavioral::read_cached_analysis(&path).unwrap();
        assert!(analysis.source.eval);
    }

    #[test]
    fn enabled_v1_cache_hit_replaces_outdated_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"outdated\",\"version\":\"1.0.0\"}",
            ),
            ("index.js", b"eval('code')"),
        ]);
        let path = store.store_package("outdated", "1.0.0", &tarball).unwrap();
        let cache_path = path.join(".lpm-security.json");
        let mut cache: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
        cache["version"] = serde_json::json!(0);
        std::fs::write(&cache_path, serde_json::to_vec(&cache).unwrap()).unwrap();

        assert!(store.has_package("outdated", "1.0.0"));

        let analysis = lpm_security::behavioral::read_cached_analysis(&path).unwrap();
        assert_eq!(analysis.version, lpm_security::behavioral::SCHEMA_VERSION);
    }

    #[test]
    fn store_security_analysis_detects_gpl() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"gpl-pkg\",\"version\":\"1.0.0\",\"license\":\"GPL-3.0\"}",
            ),
            ("index.js", b"module.exports = 42"),
        ]);

        let path = store.store_package("gpl-pkg", "1.0.0", &tarball).unwrap();
        let content = std::fs::read_to_string(path.join(".lpm-security.json")).unwrap();
        let analysis: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(analysis["manifest"]["copyleftLicense"], true);
    }

    #[test]
    fn store_cache_hit_preserves_security_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"cached\",\"version\":\"1.0.0\",\"license\":\"MIT\"}",
            ),
            ("index.js", b"eval('test')"),
        ]);

        let path1 = store.store_package("cached", "1.0.0", &tarball).unwrap();
        assert!(path1.join(".lpm-security.json").exists());

        let path2 = store.store_package("cached", "1.0.0", &tarball).unwrap();
        assert!(path2.join(".lpm-security.json").exists());

        let analysis = lpm_security::behavioral::read_cached_analysis(&path2);
        assert!(analysis.is_some(), "cached analysis should be readable");
        assert!(analysis.unwrap().source.eval);
    }

    #[test]
    fn integrity_mismatch_detected() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"tamper\",\"version\":\"1.0.0\"}",
        )]);

        let path = store.store_package("tamper", "1.0.0", &tarball).unwrap();
        std::fs::write(path.join(".integrity"), "sha512-TAMPERED").unwrap();

        let stored = read_stored_integrity(&path).unwrap();
        let expected = compute_sri_hash(&tarball);
        assert_ne!(stored, expected, "tampered integrity should not match");
    }

    #[test]
    fn hashing_reader_produces_matching_digests_for_supported_algorithms() {
        let data = b"hello world";
        let mut reader = HashingReader::new(std::io::Cursor::new(data));
        let _ = std::io::copy(&mut reader, &mut std::io::sink()).unwrap();
        let (sha512_sri, sha256_sri, sha1_sri, bytes) = reader.finalize();

        assert_eq!(bytes, data.len() as u64);
        assert_eq!(sha512_sri, compute_sri_hash(data));
        assert_eq!(sha256_sri, compute_sri_hash_sha256(data));
        assert_eq!(sha1_sri, compute_sri_hash_sha1(data));
        assert!(sha512_sri.starts_with("sha512-"));
        assert!(sha256_sri.starts_with("sha256-"));
        assert!(sha1_sri.starts_with("sha1-"));
    }

    #[test]
    fn store_concurrent_same_package_no_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"race\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 42"),
        ]);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = PackageStore::at(dir.path());
                let tarball = tarball.clone();
                std::thread::spawn(move || store.store_package("race", "1.0.0", &tarball))
            })
            .collect();

        for handle in handles {
            let result = handle.join().expect("thread panicked");
            assert!(result.is_ok(), "store_package failed: {:?}", result.err());
        }

        let store = PackageStore::at(dir.path());
        assert!(store.has_package("race", "1.0.0"));
        let pkg_dir = store.package_dir("race", "1.0.0");
        assert!(pkg_dir.join("package.json").exists());
        assert!(pkg_dir.join("index.js").exists());

        let v1_dir = dir.path().join("v1");
        if v1_dir.exists() {
            for entry in std::fs::read_dir(&v1_dir).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().to_string();
                assert!(
                    !name.contains(".tmp."),
                    "stale temp directory found: {name}"
                );
            }
        }
    }

    #[test]
    fn store_package_extract_failure_cleans_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = store.package_dir("broken", "1.0.0").with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            thread_id
        ));

        let result = store.store_package("broken", "1.0.0", b"not-a-tarball");

        assert!(result.is_err(), "invalid tarball should fail extraction");
        assert!(
            !tmp_dir.exists(),
            "failed extraction should not leave a stale temp dir: {}",
            tmp_dir.display()
        );
    }

    #[test]
    fn store_package_integrity_write_failure_cleans_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"broken\",\"version\":\"1.0.0\"}",
            ),
            (".integrity/nested.txt", b"shadowed integrity path"),
        ]);
        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = store.package_dir("broken", "1.0.0").with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            thread_id
        ));

        let result = store.store_package("broken", "1.0.0", &tarball);

        assert!(
            result.is_err(),
            "integrity write should fail when .integrity is a directory"
        );
        assert!(
            !tmp_dir.exists(),
            "integrity write failure should not leave a stale temp dir: {}",
            tmp_dir.display()
        );
    }

    #[test]
    fn store_from_file_creates_package() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tgz = create_test_tarball(&[
            ("package.json", br#"{"name":"file-test","version":"1.0.0"}"#),
            ("index.js", b"exports.run = () => 'file-based'"),
        ]);

        let mut temp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut temp, &tgz).unwrap();

        let sri = "sha512-test-hash";
        let path = store
            .store_package_from_file("file-test", "1.0.0", temp.path(), sri)
            .unwrap();

        assert!(store.has_package("file-test", "1.0.0"));
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());
        let stored_sri = std::fs::read_to_string(path.join(".integrity")).unwrap();
        assert_eq!(stored_sri, sri);
    }

    #[test]
    fn store_from_file_cache_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tgz =
            create_test_tarball(&[("package.json", br#"{"name":"cached","version":"1.0.0"}"#)]);

        store.store_package("cached", "1.0.0", &tgz).unwrap();
        assert!(store.has_package("cached", "1.0.0"));

        let mut temp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut temp, &tgz).unwrap();
        let path = store
            .store_package_from_file("cached", "1.0.0", temp.path(), "sha512-x")
            .unwrap();

        assert!(path.join("package.json").exists());
    }

    #[test]
    fn store_from_file_concurrent_same_package() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(PackageStore::at(dir.path()));
        let tgz = create_test_tarball(&[
            ("package.json", br#"{"name":"race","version":"1.0.0"}"#),
            ("index.js", b"module.exports = 'race'"),
        ]);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = store.clone();
                let data = tgz.clone();
                std::thread::spawn(move || {
                    let mut temp = tempfile::NamedTempFile::new().unwrap();
                    std::io::Write::write_all(&mut temp, &data).unwrap();
                    s.store_package_from_file("race", "1.0.0", temp.path(), "sha512-race")
                })
            })
            .collect();

        for h in handles {
            let result: Result<PathBuf, _> = h.join().unwrap();
            assert!(result.is_ok(), "concurrent store_from_file should not fail");
        }

        assert!(store.has_package("race", "1.0.0"));
        let store_v1 = store.root().join("v1");
        if store_v1.exists() {
            for entry in std::fs::read_dir(&store_v1).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().to_string();
                assert!(!name.contains(".tmp."), "stale temp dir found: {name}");
            }
        }
    }

    #[test]
    fn store_from_file_extract_failure_cleans_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let bad_tarball = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(bad_tarball.path(), b"not-a-tarball").unwrap();

        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = store
            .package_dir("broken-file", "1.0.0")
            .with_extension(format!("tmp.{}.{}", std::process::id(), thread_id));

        let result =
            store.store_package_from_file("broken-file", "1.0.0", bad_tarball.path(), "sha512-bad");

        assert!(
            result.is_err(),
            "invalid tarball file should fail extraction"
        );
        assert!(
            !tmp_dir.exists(),
            "failed file extraction should not leave a stale temp dir: {}",
            tmp_dir.display()
        );
    }

    #[test]
    fn store_from_file_integrity_write_failure_cleans_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                br#"{"name":"broken-file","version":"1.0.0"}"#,
            ),
            (".integrity/nested.txt", b"shadowed integrity path"),
        ]);
        let tarball_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tarball_file.path(), &tarball).unwrap();

        let thread_id = format!("{:?}", std::thread::current().id());
        let tmp_dir = store
            .package_dir("broken-file", "1.0.0")
            .with_extension(format!("tmp.{}.{}", std::process::id(), thread_id));

        let result = store.store_package_from_file(
            "broken-file",
            "1.0.0",
            tarball_file.path(),
            "sha512-bad",
        );

        assert!(
            result.is_err(),
            "integrity write should fail when .integrity is a directory"
        );
        assert!(
            !tmp_dir.exists(),
            "integrity write failure should not leave a stale temp dir: {}",
            tmp_dir.display()
        );
    }
}
