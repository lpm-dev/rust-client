use std::path::PathBuf;

use lpm_common::LpmError;
use lpm_common::integrity::{HashAlgorithm, Integrity};
use sha1::Sha1;
use sha2::{Digest, Sha512};

use crate::integrity::integrity_strength;
use crate::{PackageStore, StageTimings, compute_sri_hash, is_complete_package_dir};

impl PackageStore {
    /// Extract a tarball into the store. Returns the store path.
    ///
    /// If the store already holds this archive at the coordinate, skips
    /// extraction (cache hit). A coordinate that holds a different archive is
    /// an integrity conflict.
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
        self.store_at_dir(dir, &label, tarball_data, EntryKey::Coordinate)
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
        key: EntryKey,
    ) -> Result<PathBuf, LpmError> {
        // Fast path: already stored
        if self.entry_is_published(&dir, label)? {
            if key == EntryKey::Coordinate {
                bind_entry_to_archive(
                    self.root(),
                    &dir,
                    label,
                    &ArchiveProof::Bytes(tarball_data),
                    &[],
                )?;
            }
            self.backfill_security_cache_if_enabled(&dir, label);
            tracing::debug!("store hit: {label}");
            return Ok(dir);
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
        if !self.publish_staged(&tmp_dir, &dir, None)? && key == EntryKey::Coordinate {
            bind_entry_to_archive(
                self.root(),
                &dir,
                label,
                &ArchiveProof::Bytes(tarball_data),
                &[],
            )?;
        }
        Ok(dir)
    }

    /// Whether a complete entry is at `dir`, after clearing an incomplete one
    /// out of a publication's way.
    fn entry_is_published(&self, dir: &std::path::Path, label: &str) -> Result<bool, LpmError> {
        if is_complete_package_dir(dir) {
            return Ok(true);
        }
        if !dir.exists() {
            return Ok(false);
        }
        let _publication = self.lock_publication()?;
        // Another process may have published the entry since the look above.
        // Only what is still incomplete under the lock is cleared.
        if is_complete_package_dir(dir) {
            return Ok(true);
        }
        match std::fs::remove_dir_all(dir) {
            Ok(()) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(LpmError::Store(format!(
                "failed to remove incomplete store entry for {label}: {error}"
            ))),
        }
    }

    /// Moves the staged entry at `tmp_dir` into place at `dir`, under the
    /// publication lock. False when a complete entry was there already, which
    /// the caller then checks like any entry it found.
    ///
    /// `outgrown` is the marker of an entry this publication replaces: one
    /// that names the same archive only under a weaker hash than the caller
    /// verified. It is moved aside only while it still carries that marker,
    /// so an entry another process published since is left alone.
    fn publish_staged(
        &self,
        tmp_dir: &std::path::Path,
        dir: &std::path::Path,
        outgrown: Option<&str>,
    ) -> Result<bool, LpmError> {
        let mut retired = tmp_dir.as_os_str().to_owned();
        retired.push(".retired");
        let retired = PathBuf::from(retired);
        let renamed = self.lock_publication().and_then(|_publication| {
            let replaced = outgrown.is_some_and(|outgrown| {
                read_integrity_marker(dir).as_deref() == Some(outgrown)
                    && std::fs::rename(dir, &retired).is_ok()
            });
            match std::fs::rename(tmp_dir, dir) {
                Ok(()) => Ok(true),
                Err(_) if dir.exists() => Ok(false),
                Err(error) => {
                    if replaced {
                        let _ = std::fs::rename(&retired, dir);
                    }
                    Err(LpmError::Store(format!("failed to store package: {error}")))
                }
            }
        });
        if !matches!(renamed, Ok(true)) {
            let _ = std::fs::remove_dir_all(tmp_dir);
        }
        // Outside the lock: removing a package's files is the slow part.
        let _ = std::fs::remove_dir_all(&retired);
        renamed
    }

    /// The lock every removal and publication of a v1 entry of this store
    /// holds. Threads of this process queue on a mutex first: the file lock
    /// is taken by polling, which would cost each of them a poll interval
    /// whenever two finish together.
    fn lock_publication(&self) -> Result<PublicationLock, LpmError> {
        // One mutex per store root, kept for the life of the process, which
        // opens a handful of stores at most.
        static BY_ROOT: std::sync::Mutex<
            std::collections::BTreeMap<PathBuf, &'static std::sync::Mutex<()>>,
        > = std::sync::Mutex::new(std::collections::BTreeMap::new());
        let of_root: &'static std::sync::Mutex<()> = BY_ROOT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(self.root().to_path_buf())
            .or_insert_with(|| Box::leak(Box::default()));
        let in_process = of_root
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(PublicationLock {
            _across_processes: lpm_common::acquire_single_file_exclusive_lock(
                self.root().join("v1-publish.lock"),
            )?,
            _in_process: in_process,
        })
    }

    /// Extract a tarball from a file into the store. Returns the store path.
    ///
    /// Bounded-memory variant of `store_package()` — reads the tarball from disk
    /// in chunks rather than requiring it in memory. The caller has verified
    /// the file against `sri` (computed during download).
    ///
    /// Same atomicity guarantees as `store_package()`: unique temp dir per
    /// process+thread, atomic rename into final location. A coordinate that
    /// already holds a different archive, or that a concurrent publication of
    /// a different archive wins, is an integrity conflict.
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
        self.store_package_from_file_timed(name, version, tarball_path, sri, None)
            .map(|(path, _)| path)
    }

    /// Extract a tarball file into a store directory named by its content.
    pub(crate) fn store_tarball_from_file_at(
        &self,
        dir: PathBuf,
        label: &str,
        tarball_path: &std::path::Path,
        sri: &str,
    ) -> Result<PathBuf, LpmError> {
        self.store_from_file_at_timed(dir, label, tarball_path, sri, None, EntryKey::Content)
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
    /// SHA-512 is always computed for canonical object identity. SHA-256 and
    /// SHA-1 are computed in the same pass so older registry declarations can
    /// be verified without re-reading or buffering the stream.
    ///
    /// ## An entry that already exists
    /// A coordinate names no bytes, so a complete entry is returned only when
    /// it holds this archive. An entry whose recorded integrity is
    /// `expected_integrity`, or a hash already verified to name the same
    /// archive, is returned without reading the stream. Otherwise the stream
    /// is hashed without extracting: an entry recorded under one of the
    /// stream's digests is returned, and any other is an integrity conflict.
    /// The winner of a concurrent publication is checked the same way.
    ///
    /// ## Failure semantics
    /// Any error after staging-dir creation cleans up the staging dir
    /// before returning.
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
        let label = format!("{name}@{version}");
        let mut timings = StageTimings::default();

        let mut outgrown = None;
        if self.entry_is_published(&dir, &label)? {
            let recorded = expected_integrity
                .filter(|expected| {
                    crate::integrity::stored_integrity_matches(self.root(), &dir, expected)
                })
                .and_then(|_| read_integrity_marker(&dir));
            outgrown = match recorded {
                Some(_) => None,
                None => weaker_marker(&dir, expected_integrity.as_slice()),
            };
            if outgrown.is_none() {
                let stored = match recorded {
                    Some(recorded) => recorded,
                    None => {
                        let mut hashing_reader =
                            HashingReader::new(SizeLimitedReader::new(reader, max_compressed_size));
                        std::io::copy(&mut hashing_reader, &mut std::io::sink())?;
                        let digests = ArchiveDigests::from(hashing_reader.finalize());
                        digests.verify_declared(&label, expected_integrity)?;
                        bind_entry_to_archive(
                            self.root(),
                            &dir,
                            &label,
                            &ArchiveProof::Digests(&digests),
                            expected_integrity.as_slice(),
                        )?
                    }
                };
                self.backfill_security_cache_if_enabled(&dir, &label);
                tracing::debug!("store hit: {label}");
                return Ok((dir, stored, timings));
            }
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
                analyzer.borrow_mut().note_entry(entry.relative_path);
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

        let digests = ArchiveDigests::from(hashing_reader.finalize());
        timings.extract_ms = extract_start.elapsed().as_millis();

        if let Err(error) = digests.verify_declared(&label, expected_integrity) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(error);
        }
        let computed_sri = digests.sha512.clone();

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
        let published = self.publish_staged(
            &tmp_dir,
            &dir,
            outgrown
                .as_deref()
                .filter(|marker| digests.contains(marker)),
        );
        timings.finalize_rename_ms = rename_start.elapsed().as_millis();
        timings.finalize_ms = finalize_start.elapsed().as_millis();
        published?;
        // Covers the entry this call published and the winner of a concurrent
        // publication alike: either is returned only as this archive.
        bind_entry_to_archive(
            self.root(),
            &dir,
            &label,
            &ArchiveProof::Digests(&digests),
            expected_integrity.as_slice(),
        )?;
        Ok((dir, computed_sri, timings))
    }

    /// Same contract as [`PackageStore::store_package_from_file`], plus a
    /// [`StageTimings`] breakdown (extract / security / finalize) for the
    /// caller. On the store-hit fast path every field is zero.
    ///
    /// `declared` is a second hash the caller verified the file against, such
    /// as the lockfile's pin in another algorithm. It is recorded as naming
    /// the stored archive, so a later lookup under it is a hit.
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
        declared: Option<&str>,
    ) -> Result<(PathBuf, StageTimings), LpmError> {
        let dir = self.package_dir(name, version);
        let label = format!("{name}@{version}");
        self.store_from_file_at_timed(
            dir,
            &label,
            tarball_path,
            sri,
            declared,
            EntryKey::Coordinate,
        )
    }

    fn store_from_file_at_timed(
        &self,
        dir: PathBuf,
        label: &str,
        tarball_path: &std::path::Path,
        sri: &str,
        declared: Option<&str>,
        key: EntryKey,
    ) -> Result<(PathBuf, StageTimings), LpmError> {
        let mut timings = StageTimings::default();
        let verified = [sri, declared.unwrap_or(sri)];
        let verified = if verified[0] == verified[1] {
            &verified[..1]
        } else {
            &verified[..]
        };
        let bind = |dir: &std::path::Path| match key {
            EntryKey::Content => Ok(()),
            EntryKey::Coordinate => bind_entry_to_archive(
                self.root(),
                dir,
                label,
                &ArchiveProof::File(tarball_path),
                verified,
            )
            .map(drop),
        };

        // Fast path: already stored. Callers on the install hot path pre-filter
        // against the store so this should rarely hit; we keep it for the
        // general-purpose API contract.
        let mut outgrown = None;
        if self.entry_is_published(&dir, label)? {
            if key == EntryKey::Coordinate {
                outgrown = weaker_marker(&dir, verified)
                    .filter(|marker| ArchiveProof::File(tarball_path).is_named_by(marker));
            }
            if outgrown.is_none() {
                bind(&dir)?;
                self.backfill_security_cache_if_enabled(&dir, label);
                tracing::debug!("store hit: {label}");
                return Ok((dir, timings));
            }
        }

        tracing::debug!("extracting {label} to store (from file)");

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
                tracing::warn!("failed to write .lpm-security.json for {label}: {e}");
            } else {
                tracing::debug!(
                    "security analysis: {label} — {} files scanned, {} bytes",
                    analysis.meta.files_scanned,
                    analysis.meta.bytes_scanned
                );
            }
            timings.security_ms = security_start.elapsed().as_millis();
        }

        // Finalize: atomic rename into the visible path.
        let rename_start = std::time::Instant::now();
        let published = self.publish_staged(&tmp_dir, &dir, outgrown.as_deref());
        timings.finalize_rename_ms = rename_start.elapsed().as_millis();
        timings.finalize_ms = timings.finalize_integrity_write_ms + timings.finalize_rename_ms;
        published?;
        bind(&dir)?;
        Ok((dir, timings))
    }
}

/// Held while a v1 entry is cleared or moved into place, so that one
/// publication never removes what another has just published.
struct PublicationLock {
    _across_processes: lpm_common::SingleFileExclusiveLockHandle,
    _in_process: std::sync::MutexGuard<'static, ()>,
}

/// The marker of the complete entry at `dir`, when it is a weaker hash than
/// one of `verified`. Such an entry was extracted from bytes checked against
/// the weaker hash alone, which doesn't show it holds the archive the
/// stronger one names. When the verified archive also has that weaker hash,
/// the entry is replaced by a fresh extraction of it; otherwise it holds
/// other bytes, and the publication ends in a conflict.
fn weaker_marker(dir: &std::path::Path, verified: &[&str]) -> Option<String> {
    let recorded = read_integrity_marker(dir).filter(|_| is_complete_package_dir(dir))?;
    let strength = integrity_strength(&recorded);
    verified
        .iter()
        .any(|sri| integrity_strength(sri) > strength)
        .then_some(recorded)
}

/// What names a store directory. A coordinate names no bytes, so an entry
/// under one is used only once it is bound to the archive being published. A
/// content-keyed directory is named by the archive's own hash.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKey {
    Coordinate,
    Content,
}

/// The archive a publication holds, in the form it can be checked against a
/// recorded integrity.
enum ArchiveProof<'a> {
    Bytes(&'a [u8]),
    File(&'a std::path::Path),
    Digests(&'a ArchiveDigests),
}

impl ArchiveProof<'_> {
    fn is_named_by(&self, recorded: &str) -> bool {
        match self {
            Self::Bytes(bytes) => {
                Integrity::parse(recorded).is_ok_and(|integrity| integrity.verify(bytes).is_ok())
            }
            Self::File(path) => Integrity::parse(recorded)
                .is_ok_and(|integrity| integrity.verify_file(path).is_ok()),
            Self::Digests(digests) => digests.contains(recorded),
        }
    }
}

/// Every digest of one archive stream, as SRI strings.
struct ArchiveDigests {
    sha512: String,
    sha256: String,
    sha1: String,
}

impl From<(String, String, String, u64)> for ArchiveDigests {
    fn from((sha512, sha256, sha1, _bytes): (String, String, String, u64)) -> Self {
        Self {
            sha512,
            sha256,
            sha1,
        }
    }
}

impl ArchiveDigests {
    fn contains(&self, sri: &str) -> bool {
        use subtle::ConstantTimeEq;
        [&self.sha512, &self.sha256, &self.sha1]
            .into_iter()
            .any(|digest| {
                digest.len() == sri.len() && digest.as_bytes().ct_eq(sri.as_bytes()).into()
            })
    }

    /// Check the stream against the algorithm `declared` names. A non-sha512
    /// declaration is compared with the matching digest, never with sha512.
    fn verify_declared(&self, label: &str, declared: Option<&str>) -> Result<(), LpmError> {
        let Some(declared) = declared else {
            return Ok(());
        };
        let computed = if declared.starts_with("sha512-") {
            &self.sha512
        } else if declared.starts_with("sha256-") {
            &self.sha256
        } else if declared.starts_with("sha1-") {
            &self.sha1
        } else {
            return Err(LpmError::Registry(format!(
                "unsupported integrity algorithm for {label}: {declared} — \
                 expected sha512-… (preferred), sha256-…, or sha1-…"
            )));
        };
        if self.contains(declared) {
            Ok(())
        } else {
            Err(LpmError::Registry(format!(
                "integrity mismatch for {label}: expected {declared}, got {computed}"
            )))
        }
    }
}

fn read_integrity_marker(dir: &std::path::Path) -> Option<String> {
    lpm_common::read_text_file_capped_nofollow(&dir.join(".integrity"), 4096).ok()
}

fn integrity_conflict(label: &str, dir: &std::path::Path) -> LpmError {
    LpmError::Store(format!(
        "v1 store integrity conflict for {label}: the entry at {} holds other bytes than the \
         ones selected. Remove that entry, or use the default v2 store or a separate LPM_HOME",
        dir.display()
    ))
}

/// Accept the complete entry at `dir` only as the archive `proof` holds, and
/// return its recorded integrity.
///
/// `verified` are hashes the caller verified that archive against. An entry
/// recorded under one of them, or under any hash that names the archive, is
/// the same archive; each other member of `verified` is then recorded as an
/// alias of the entry, so a later lookup under it is a hit. Any other entry
/// holds different bytes at the same coordinate.
///
/// An entry recorded under a weaker algorithm than one of `verified` is
/// refused as well: matching it would vouch for the stronger hash on the
/// weaker one's word.
fn bind_entry_to_archive(
    store_root: &std::path::Path,
    dir: &std::path::Path,
    label: &str,
    proof: &ArchiveProof<'_>,
    verified: &[&str],
) -> Result<String, LpmError> {
    let recorded = read_integrity_marker(dir).ok_or_else(|| integrity_conflict(label, dir))?;
    if !is_complete_package_dir(dir) {
        // Every incomplete entry was cleared before this publication, so the
        // one here is what the archive itself extracts to.
        return Err(LpmError::Store(format!(
            "the archive of {label} has no package.json at its root, so it can't be stored"
        )));
    }
    let recorded_strength = integrity_strength(&recorded);
    let same_archive = verified.contains(&recorded.as_str()) || proof.is_named_by(&recorded);
    let strong_enough = verified
        .iter()
        .all(|sri| *sri == recorded || integrity_strength(sri) <= recorded_strength);
    if !same_archive || !strong_enough {
        return Err(integrity_conflict(label, dir));
    }
    for sri in verified {
        // The alias only saves the next lookup a download.
        if *sri != recorded
            && let Err(error) =
                crate::integrity::record_verified_integrity_alias(store_root, &recorded, sri)
        {
            tracing::warn!("failed to record a verified integrity alias for {label}: {error}");
        }
    }
    Ok(recorded)
}

#[derive(Clone)]
enum CanonicalSha512 {
    Computing(Sha512),
    Known([u8; 64]),
}

impl CanonicalSha512 {
    fn finalize(self) -> [u8; 64] {
        match self {
            Self::Computing(hasher) => hasher.finalize().into(),
            Self::Known(digest) => digest,
        }
    }
}

/// Transparent `Read` wrapper that computes the canonical SHA-512 tarball
/// identity inline with extraction. The declared-integrity constructor adds
/// SHA-256 or SHA-1 only when the declaration requires it.
pub(crate) struct HashingReader<R> {
    inner: R,
    sha512: CanonicalSha512,
    sha256: Option<sha2::Sha256>,
    sha1: Option<Sha1>,
    bytes: u64,
}

pub(crate) trait StreamingIntegrityReader: std::io::Read {
    fn canonical_sha512_sri(&self) -> String;
    fn integrity_matches(&self, expected: &Integrity) -> Option<bool>;
    fn integrity_sri(&self, algorithm: HashAlgorithm) -> Option<String>;
}

impl<R: std::io::Read> HashingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        use sha2::Digest;
        Self {
            inner,
            sha512: CanonicalSha512::Computing(Sha512::new()),
            sha256: Some(sha2::Sha256::new()),
            sha1: Some(Sha1::new()),
            bytes: 0,
        }
    }

    pub(crate) fn for_expected_integrity(
        inner: R,
        expected_integrity: Option<&str>,
    ) -> Result<Self, LpmError> {
        let expected_algorithm = expected_integrity
            .map(Integrity::parse)
            .transpose()?
            .map(|integrity| integrity.algorithm);
        Ok(Self {
            inner,
            sha512: CanonicalSha512::Computing(Sha512::new()),
            sha256: matches!(expected_algorithm, Some(HashAlgorithm::Sha256))
                .then(sha2::Sha256::new),
            sha1: matches!(expected_algorithm, Some(HashAlgorithm::Sha1)).then(Sha1::new),
            bytes: 0,
        })
    }

    pub(crate) fn with_known_sha512(
        inner: R,
        canonical_sri: &str,
        expected_integrity: Option<&str>,
    ) -> Result<Self, LpmError> {
        let canonical = Integrity::parse(canonical_sri)?;
        if canonical.algorithm != HashAlgorithm::Sha512 {
            return Err(LpmError::Store(
                "known tarball identity must use SHA-512".into(),
            ));
        }
        let digest: [u8; 64] = canonical.hash.try_into().map_err(|_| {
            LpmError::Store("known tarball SHA-512 identity must contain 64 bytes".into())
        })?;
        let mut reader = Self::for_expected_integrity(inner, expected_integrity)?;
        reader.sha512 = CanonicalSha512::Known(digest);
        Ok(reader)
    }

    /// Finalize all hashers and return `(sha512_sri, sha256_sri, sha1_sri, total_bytes)`.
    /// Consumes `self` because the hashers are one-shot.
    pub(crate) fn finalize(self) -> (String, String, String, u64) {
        use base64::Engine;
        let sha512_digest = self.sha512.finalize();
        let sha256_digest = self
            .sha256
            .expect("default hashing reader includes sha256")
            .finalize();
        let sha1_digest = self
            .sha1
            .expect("default hashing reader includes sha1")
            .finalize();
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

impl<R: std::io::Read> StreamingIntegrityReader for HashingReader<R> {
    fn canonical_sha512_sri(&self) -> String {
        use base64::Engine;
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(self.sha512.clone().finalize())
        )
    }

    fn integrity_matches(&self, expected: &Integrity) -> Option<bool> {
        use subtle::ConstantTimeEq;
        let matches = |computed: &[u8]| {
            expected.hash.len() == computed.len()
                && bool::from(expected.hash.as_slice().ct_eq(computed))
        };
        match expected.algorithm {
            HashAlgorithm::Sha512 => Some(matches(self.sha512.clone().finalize().as_slice())),
            HashAlgorithm::Sha256 => self
                .sha256
                .as_ref()
                .map(|hasher| matches(hasher.clone().finalize().as_slice())),
            HashAlgorithm::Sha1 => self
                .sha1
                .as_ref()
                .map(|hasher| matches(hasher.clone().finalize().as_slice())),
        }
    }

    fn integrity_sri(&self, algorithm: HashAlgorithm) -> Option<String> {
        use base64::Engine;
        let encoded = match algorithm {
            HashAlgorithm::Sha512 => {
                base64::engine::general_purpose::STANDARD.encode(self.sha512.clone().finalize())
            }
            HashAlgorithm::Sha256 => base64::engine::general_purpose::STANDARD
                .encode(self.sha256.as_ref()?.clone().finalize()),
            HashAlgorithm::Sha1 => base64::engine::general_purpose::STANDARD
                .encode(self.sha1.as_ref()?.clone().finalize()),
        };
        let algorithm = match algorithm {
            HashAlgorithm::Sha512 => "sha512",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha1 => "sha1",
        };
        Some(format!("{algorithm}-{encoded}"))
    }
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.read(buf)?;
        if n > 0 {
            if let CanonicalSha512::Computing(hasher) = &mut self.sha512 {
                hasher.update(&buf[..n]);
            }
            if let Some(hasher) = &mut self.sha256 {
                hasher.update(&buf[..n]);
            }
            if let Some(hasher) = &mut self.sha1 {
                hasher.update(&buf[..n]);
            }
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
pub(crate) struct SizeLimitedReader<R> {
    inner: R,
    bytes_read: u64,
    limit: u64,
}

impl<R: std::io::Read> SizeLimitedReader<R> {
    pub(crate) fn new(inner: R, limit: u64) -> Self {
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
    fn known_sha512_reader_reuses_the_digest_without_rehashing_stream_bytes() {
        let bytes = b"already downloaded and hashed";
        let canonical = compute_sri_hash(bytes);
        let expected = compute_sri_hash_sha256(bytes);
        let mut reader =
            HashingReader::with_known_sha512(bytes.as_slice(), &canonical, Some(&expected))
                .unwrap();
        std::io::copy(&mut reader, &mut std::io::sink()).unwrap();
        assert!(matches!(reader.sha512, CanonicalSha512::Known(_)));
        assert_eq!(reader.canonical_sha512_sri(), canonical);
        assert_eq!(reader.integrity_sri(HashAlgorithm::Sha256), Some(expected));
        assert!(reader.sha1.is_none());
        assert_eq!(reader.bytes, bytes.len() as u64);
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
            .store_package_from_file("cached", "1.0.0", temp.path(), &compute_sri_hash(&tgz))
            .unwrap();

        assert!(path.join("package.json").exists());
    }

    #[test]
    fn pinned_file_insertions_reject_a_different_concurrent_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
                .into_iter()
                .map(|marker| {
                    let store = &store;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let bytes = create_test_tarball(&[
                            ("package.json", br#"{"name":"race","version":"1.0.0"}"#),
                            ("marker.txt", marker),
                        ]);
                        let sri = compute_sri_hash(&bytes);
                        let mut archive = tempfile::NamedTempFile::new().unwrap();
                        std::io::Write::write_all(&mut archive, &bytes).unwrap();
                        barrier.wait();
                        store.store_package_from_file("race", "1.0.0", archive.path(), &sri)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "{results:?}"
        );
        let error = results
            .iter()
            .find_map(|result| result.as_ref().err())
            .unwrap();
        assert!(error.to_string().contains("integrity conflict"), "{error}");
        let winner = results.iter().position(Result::is_ok).unwrap();
        assert_eq!(
            std::fs::read(store.package_dir("race", "1.0.0").join("marker.txt")).unwrap(),
            if winner == 0 {
                b"first".as_slice()
            } else {
                b"second".as_slice()
            }
        );
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
                    s.store_package_from_file(
                        "race",
                        "1.0.0",
                        temp.path(),
                        &compute_sri_hash(&data),
                    )
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
    fn pinned_file_insertions_accept_the_same_concurrent_artifact() {
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
                    s.store_package_from_file(
                        "race",
                        "1.0.0",
                        temp.path(),
                        &compute_sri_hash(&data),
                    )
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

    const STREAM_LIMIT: u64 = 1024 * 1024;

    fn marked_archive(marker: &[u8]) -> Vec<u8> {
        create_test_tarball(&[
            ("package.json", br#"{"name":"same","version":"1.0.0"}"#),
            ("marker.txt", marker),
        ])
    }

    fn stored_marker(store: &PackageStore) -> Vec<u8> {
        std::fs::read(store.package_dir("same", "1.0.0").join("marker.txt")).unwrap()
    }

    struct UnreadableStream;

    impl std::io::Read for UnreadableStream {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("the stream must not be read"))
        }
    }

    #[test]
    fn stream_rejects_a_complete_coordinate_that_holds_a_different_archive() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let original = marked_archive(b"original");
        let replacement = marked_archive(b"replacement");
        store.store_package("same", "1.0.0", &original).unwrap();

        let error = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&replacement),
                Some(&compute_sri_hash(&replacement)),
                STREAM_LIMIT,
            )
            .unwrap_err();

        assert!(error.to_string().contains("integrity conflict"), "{error}");
        assert_eq!(stored_marker(&store), b"original");
        assert_eq!(
            read_stored_integrity(&store.package_dir("same", "1.0.0")).unwrap(),
            compute_sri_hash(&original)
        );
    }

    #[test]
    fn stream_without_a_declared_integrity_rejects_a_different_archive_at_the_coordinate() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        store
            .store_package("same", "1.0.0", &marked_archive(b"original"))
            .unwrap();

        let error = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(marked_archive(b"replacement")),
                None,
                STREAM_LIMIT,
            )
            .unwrap_err();

        assert!(error.to_string().contains("integrity conflict"), "{error}");
        assert_eq!(stored_marker(&store), b"original");
    }

    #[test]
    fn stream_hit_under_the_recorded_integrity_does_not_read_the_stream() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let archive = marked_archive(b"original");
        let sri = compute_sri_hash(&archive);
        let dir = store.store_package("same", "1.0.0", &archive).unwrap();

        let (path, returned, _) = store
            .stream_and_store_package("same", "1.0.0", UnreadableStream, Some(&sri), STREAM_LIMIT)
            .unwrap();

        assert_eq!(path, dir);
        assert_eq!(returned, sri);
    }

    #[test]
    fn stream_accepts_an_alternate_hash_only_after_the_archive_proves_it() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let archive = marked_archive(b"original");
        let sha256 = compute_sri_hash_sha256(&archive);
        store.store_package("same", "1.0.0", &archive).unwrap();
        assert!(!store.has_package_matching_integrity("same", "1.0.0", &sha256));

        let unproven = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(Vec::new()),
                Some(&sha256),
                STREAM_LIMIT,
            )
            .unwrap_err();
        assert!(
            unproven.to_string().contains("integrity mismatch"),
            "{unproven}"
        );
        assert!(!store.has_package_matching_integrity("same", "1.0.0", &sha256));

        let (_, returned, _) = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&archive),
                Some(&sha256),
                STREAM_LIMIT,
            )
            .unwrap();
        assert_eq!(returned, compute_sri_hash(&archive));
        assert!(store.has_package_matching_integrity("same", "1.0.0", &sha256));
        store
            .stream_and_store_package(
                "same",
                "1.0.0",
                UnreadableStream,
                Some(&sha256),
                STREAM_LIMIT,
            )
            .expect("a proven alternate hash is a hit without the archive");
    }

    #[test]
    fn stream_publication_records_the_declared_hash_for_later_lookups() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let archive = marked_archive(b"original");
        let sha1 = compute_sri_hash_sha1(&archive);

        let (dir, returned, _) = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&archive),
                Some(&sha1),
                STREAM_LIMIT,
            )
            .unwrap();

        assert_eq!(returned, compute_sri_hash(&archive));
        assert_eq!(read_stored_integrity(&dir).unwrap(), returned);
        assert!(store.has_package_matching_integrity("same", "1.0.0", &sha1));
        assert!(!store.has_package_matching_integrity(
            "same",
            "1.0.0",
            &compute_sri_hash_sha1(&marked_archive(b"replacement"))
        ));
    }

    #[test]
    fn streamed_insertions_reject_a_different_concurrent_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
                .into_iter()
                .map(|marker| {
                    let store = &store;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let bytes = marked_archive(marker);
                        let sri = compute_sri_hash(&bytes);
                        barrier.wait();
                        store
                            .stream_and_store_package(
                                "same",
                                "1.0.0",
                                std::io::Cursor::new(bytes),
                                Some(&sri),
                                STREAM_LIMIT,
                            )
                            .map(|(_, sri, _)| sri)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "{results:?}"
        );
        let error = results
            .iter()
            .find_map(|result| result.as_ref().err())
            .unwrap();
        assert!(error.to_string().contains("integrity conflict"), "{error}");
        let winner = results.iter().position(Result::is_ok).unwrap();
        assert_eq!(
            stored_marker(&store),
            if winner == 0 {
                b"first".as_slice()
            } else {
                b"second".as_slice()
            }
        );
        assert_eq!(
            read_stored_integrity(&store.package_dir("same", "1.0.0")).unwrap(),
            *results[winner].as_ref().unwrap()
        );
    }

    #[test]
    fn in_memory_insertion_rejects_a_different_archive_at_a_complete_coordinate() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        store
            .store_package("same", "1.0.0", &marked_archive(b"original"))
            .unwrap();

        let error = store
            .store_package("same", "1.0.0", &marked_archive(b"replacement"))
            .unwrap_err();

        assert!(error.to_string().contains("integrity conflict"), "{error}");
        assert_eq!(stored_marker(&store), b"original");
    }

    #[test]
    fn file_insertion_rejects_a_different_archive_at_a_complete_coordinate() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        store
            .store_package("same", "1.0.0", &marked_archive(b"original"))
            .unwrap();
        let replacement = marked_archive(b"replacement");
        let mut archive = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut archive, &replacement).unwrap();

        let error = store
            .store_package_from_file_timed(
                "same",
                "1.0.0",
                archive.path(),
                &compute_sri_hash(&replacement),
                None,
            )
            .unwrap_err();

        assert!(error.to_string().contains("integrity conflict"), "{error}");
        assert_eq!(stored_marker(&store), b"original");
    }

    #[test]
    fn file_insertion_records_the_declared_hash_for_later_lookups() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let bytes = marked_archive(b"original");
        let sha512 = compute_sri_hash(&bytes);
        let sha1 = compute_sri_hash_sha1(&bytes);
        let mut archive = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut archive, &bytes).unwrap();

        let (dir, _) = store
            .store_package_from_file_timed("same", "1.0.0", archive.path(), &sha512, Some(&sha1))
            .unwrap();

        assert_eq!(read_stored_integrity(&dir).unwrap(), sha512);
        assert!(store.has_package_matching_integrity("same", "1.0.0", &sha1));

        let sha256 = compute_sri_hash_sha256(&bytes);
        store
            .store_package_from_file_timed("same", "1.0.0", archive.path(), &sha512, Some(&sha256))
            .unwrap();
        assert!(store.has_package_matching_integrity("same", "1.0.0", &sha256));
    }

    /// `same@1.0.0` as an LPM that recorded the lockfile's own algorithm left
    /// it: under the archive's SHA-1 alone. The extra file tells that entry
    /// from a fresh extraction of the archive.
    fn weakly_recorded_entry(store: &PackageStore, bytes: &[u8]) -> PathBuf {
        let mut archive = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut archive, bytes).unwrap();
        let (dir, _) = store
            .store_package_from_file_timed(
                "same",
                "1.0.0",
                archive.path(),
                &compute_sri_hash_sha1(bytes),
                None,
            )
            .unwrap();
        std::fs::write(dir.join("left-behind.txt"), b"").unwrap();
        dir
    }

    /// The names under the v1 directory, which hold nothing but entries once
    /// a publication is over.
    fn v1_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_stronger_pin_extracts_the_archive_again_over_a_weaker_record_from_a_stream() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let bytes = marked_archive(b"original");
        let sha512 = compute_sri_hash(&bytes);
        let dir = weakly_recorded_entry(&store, &bytes);
        assert!(!store.has_package_matching_integrity("same", "1.0.0", &sha512));

        let (stored_at, recorded, _) = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&bytes),
                Some(&sha512),
                STREAM_LIMIT,
            )
            .expect("the same archive replaces its weaker record");

        assert_eq!(
            (stored_at.as_path(), recorded.as_str()),
            (dir.as_path(), sha512.as_str())
        );
        assert_eq!(read_stored_integrity(&dir).unwrap(), sha512);
        assert!(!dir.join("left-behind.txt").exists());
        assert_eq!(stored_marker(&store), b"original");
        assert_eq!(v1_names(&dir), ["same@1.0.0"]);
        assert!(store.has_package_matching_integrity("same", "1.0.0", &sha512));
    }

    #[test]
    fn a_stronger_pin_extracts_the_archive_again_over_a_weaker_record_from_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let bytes = marked_archive(b"original");
        let sha1 = compute_sri_hash_sha1(&bytes);
        let sha512 = compute_sri_hash(&bytes);
        let dir = weakly_recorded_entry(&store, &bytes);
        let mut archive = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut archive, &bytes).unwrap();

        store
            .store_package_from_file_timed("same", "1.0.0", archive.path(), &sha512, Some(&sha1))
            .expect("the same archive replaces its weaker record");

        assert_eq!(read_stored_integrity(&dir).unwrap(), sha512);
        assert!(!dir.join("left-behind.txt").exists());
        assert_eq!(v1_names(&dir), ["same@1.0.0"]);
        assert!(store.has_package_matching_integrity("same", "1.0.0", &sha512));
        assert!(store.has_package_matching_integrity("same", "1.0.0", &sha1));
    }

    #[test]
    fn a_weaker_record_of_another_archive_is_a_conflict_for_a_stronger_pin() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let dir = weakly_recorded_entry(&store, &marked_archive(b"original"));
        let other = marked_archive(b"replacement");
        let sha512 = compute_sri_hash(&other);
        let mut archive = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut archive, &other).unwrap();

        let streamed = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&other),
                Some(&sha512),
                STREAM_LIMIT,
            )
            .unwrap_err();
        let from_file = store
            .store_package_from_file_timed("same", "1.0.0", archive.path(), &sha512, None)
            .unwrap_err();

        for error in [streamed, from_file] {
            assert!(error.to_string().contains("integrity conflict"), "{error}");
        }
        assert!(dir.join("left-behind.txt").exists());
        assert_eq!(stored_marker(&store), b"original");
        assert_eq!(v1_names(&dir), ["same@1.0.0"]);
    }

    #[test]
    fn the_pin_a_weaker_record_was_made_under_is_still_a_hit() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let bytes = marked_archive(b"original");
        let dir = weakly_recorded_entry(&store, &bytes);

        store
            .stream_and_store_package(
                "same",
                "1.0.0",
                UnreadableStream,
                Some(&compute_sri_hash_sha1(&bytes)),
                STREAM_LIMIT,
            )
            .expect("the entry answers for the hash it was recorded under");
        assert!(dir.join("left-behind.txt").exists());
    }

    #[test]
    fn an_alias_to_a_stronger_hash_left_by_an_older_lpm_does_not_vouch_for_the_entry() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let bytes = marked_archive(b"original");
        let sha1 = compute_sri_hash_sha1(&bytes);
        let sha512 = compute_sri_hash(&bytes);
        let dir = weakly_recorded_entry(&store, &bytes);
        crate::integrity::record_verified_integrity_alias(store.root(), &sha1, &sha512).unwrap();

        assert!(!store.has_package_matching_integrity("same", "1.0.0", &sha512));
        store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&bytes),
                Some(&sha512),
                STREAM_LIMIT,
            )
            .expect("the archive is read and extracted again");

        assert!(!dir.join("left-behind.txt").exists());
        assert_eq!(read_stored_integrity(&dir).unwrap(), sha512);
    }

    #[test]
    fn an_archive_without_a_root_package_json_says_so() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let bytes = create_test_tarball(&[("index.js", b"module.exports = 1")]);

        let error = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&bytes),
                Some(&compute_sri_hash(&bytes)),
                STREAM_LIMIT,
            )
            .unwrap_err();

        assert!(error.to_string().contains("no package.json"), "{error}");
    }

    #[test]
    fn hashing_an_existing_entry_keeps_the_size_limit_and_rejects_an_unknown_algorithm() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let archive = marked_archive(b"original");
        store.store_package("same", "1.0.0", &archive).unwrap();

        let oversized = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&archive),
                Some(&compute_sri_hash_sha256(&archive)),
                8,
            )
            .unwrap_err();
        assert!(
            oversized.to_string().contains("maximum compressed size"),
            "{oversized}"
        );
        let unknown = store
            .stream_and_store_package(
                "same",
                "1.0.0",
                std::io::Cursor::new(&archive),
                Some("md5-AAAA"),
                STREAM_LIMIT,
            )
            .unwrap_err();
        assert!(
            unknown
                .to_string()
                .contains("unsupported integrity algorithm"),
            "{unknown}"
        );
    }

    #[test]
    fn an_entry_published_since_it_looked_incomplete_is_not_cleared() {
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());
        let dir = store
            .store_package("same", "1.0.0", &marked_archive(b"original"))
            .unwrap();

        assert!(store.entry_is_published(&dir, "same@1.0.0").unwrap());
        assert_eq!(stored_marker(&store), b"original");

        std::fs::remove_file(dir.join(".integrity")).unwrap();
        assert!(!store.entry_is_published(&dir, "same@1.0.0").unwrap());
        assert!(!dir.exists(), "an incomplete entry is cleared");
    }

    /// Publishes `archive` through `publish` on another thread, and lets the
    /// entry of `other` appear at the coordinate after that publication has
    /// looked for one and before it moves its own into place.
    fn publish_after_another_archive_wins(
        store: &PackageStore,
        other: &[u8],
        publish: impl FnOnce(&PackageStore) -> Result<(), LpmError> + Send,
    ) -> Result<(), LpmError> {
        let dir = store.package_dir("same", "1.0.0");
        std::fs::create_dir_all(store.root()).unwrap();
        let publication = store.lock_publication().unwrap();
        std::thread::scope(|scope| {
            let loser = scope.spawn(|| publish(store));
            let staged = || {
                std::fs::read_dir(dir.parent().unwrap()).is_ok_and(|entries| {
                    entries
                        .flatten()
                        .any(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
                })
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !staged() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the publication never staged"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let winner = tempfile::tempdir().unwrap();
            let staged_winner = PackageStore::at(winner.path())
                .store_package("same", "1.0.0", other)
                .unwrap();
            std::fs::rename(staged_winner, &dir).unwrap();
            drop(publication);
            loser.join().unwrap()
        })
    }

    fn assert_no_staging_directory_is_left(store: &PackageStore) {
        for entry in std::fs::read_dir(store.root().join("v1")).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.contains(".tmp."), "stale staging directory {name}");
        }
    }

    #[test]
    fn each_publication_path_rejects_a_different_archive_that_wins_the_rename() {
        let winner = marked_archive(b"winner");
        let loser = marked_archive(b"loser");
        let sri = compute_sri_hash(&loser);
        let mut loser_file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut loser_file, &loser).unwrap();
        type Publish<'a> = Box<dyn Fn(&PackageStore) -> Result<(), LpmError> + Send + Sync + 'a>;
        let paths: [(&str, Publish<'_>); 3] = [
            (
                "in memory",
                Box::new(|store| store.store_package("same", "1.0.0", &loser).map(drop)),
            ),
            (
                "from a file",
                Box::new(|store| {
                    store
                        .store_package_from_file("same", "1.0.0", loser_file.path(), &sri)
                        .map(drop)
                }),
            ),
            (
                "streamed",
                Box::new(|store| {
                    store
                        .stream_and_store_package(
                            "same",
                            "1.0.0",
                            std::io::Cursor::new(&loser),
                            Some(&sri),
                            STREAM_LIMIT,
                        )
                        .map(drop)
                }),
            ),
        ];
        for (path, publish) in &paths {
            let directory = tempfile::tempdir().unwrap();
            let store = PackageStore::at(directory.path());

            let error = publish_after_another_archive_wins(&store, &winner, |store| publish(store))
                .expect_err(path);

            assert!(
                error.to_string().contains("integrity conflict"),
                "{path}: {error}"
            );
            assert_eq!(stored_marker(&store), b"winner", "{path}");
            assert_no_staging_directory_is_left(&store);
        }
    }

    #[test]
    fn a_streamed_publication_accepts_the_same_archive_winning_the_rename() {
        let archive = marked_archive(b"same bytes");
        let directory = tempfile::tempdir().unwrap();
        let store = PackageStore::at(directory.path());

        publish_after_another_archive_wins(&store, &archive, |store| {
            store
                .stream_and_store_package(
                    "same",
                    "1.0.0",
                    std::io::Cursor::new(&archive),
                    Some(&compute_sri_hash(&archive)),
                    STREAM_LIMIT,
                )
                .map(drop)
        })
        .unwrap();

        assert_eq!(stored_marker(&store), b"same bytes");
        assert_no_staging_directory_is_left(&store);
    }
}
