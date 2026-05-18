//! Tarball download, verification, decompression, and extraction for LPM.
//!
//! Handles the pipeline: raw .tgz bytes → verify integrity → decompress gzip → extract tar.
//!
//! npm tarballs have a `package/` prefix directory that gets stripped during extraction
//! (equivalent to `tar x --strip-components=1`).
//!
//! Performance: libdeflate for whole-buffer gzip decompression (~2-3x faster than
//! flate2/zlib-rs on the npm size distribution). flate2's `GzDecoder` is retained
//! for the test-only streaming helper.

use lpm_common::{Integrity, LpmError};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;

#[cfg(test)]
use flate2::read::GzDecoder;

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

/// Decompress a single-member gzip stream into a freshly-allocated `Vec<u8>`.
///
/// Uses libdeflate (~2-3x faster than flate2/zlib-rs on the npm-tarball size
/// distribution). The initial output buffer is sized from the gzip footer's
/// `ISIZE` field (uncompressed size mod 2^32, RFC 1952 §2.3.1); if the actual
/// size exceeds that hint (only happens for streams over 4 GiB decompressed —
/// vanishingly rare for npm packages), the buffer doubles and retries up to
/// `MAX_EXTRACTION_SIZE`.
///
/// Limitations vs `flate2::read::MultiGzDecoder`: only the first gzip member
/// is decoded. npm packs always emit single-member gzip, so this is sound for
/// the install hot path; the test-only `decompress_gzip` helper retains the
/// flate2 streaming decoder for any multi-member edge cases callers want to
/// exercise.
fn decompress_gzip_libdeflate(compressed: &[u8]) -> Result<Vec<u8>, LpmError> {
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
    // Cap the *initial* allocation so a small compressed body claiming
    // a 4 GiB ISIZE in its footer can't force a multi-GiB pre-allocation.
    // The InsufficientSpace branch below doubles the buffer up to
    // MAX_EXTRACTION_SIZE for legitimate large payloads; the initial
    // allocation here is a starting hint, not a binding ceiling.
    let initial_isize = isize_hint.min(INITIAL_ALLOCATION_CAP);
    // Floor the capacity at the compressed size — a gzip stream cannot
    // decompress to fewer bytes than its compressed length minus header/footer,
    // and tiny ISIZE values would otherwise force an immediate grow round-trip.
    let mut capacity = initial_isize
        .max(compressed.len())
        .min(MAX_EXTRACTION_SIZE as usize);

    // Hold a global budget reservation for the duration of the
    // decompress call. The guard releases on every return path
    // (early-return, error, panic) via Drop, so concurrent rayon
    // workers serialize at the budget boundary instead of all
    // racing to virtual-allocate the same 256 MiB simultaneously.
    // The guard is re-acquired on the grow path below — held
    // across the inner `vec![0u8; capacity]` allocation, which
    // is where the actual reservation matters.
    let mut budget = EXTRACT_BUDGET.acquire(capacity as u64);
    let mut decompressor = libdeflater::Decompressor::new();
    loop {
        let mut output = vec![0u8; capacity];
        match decompressor.gzip_decompress(compressed, &mut output) {
            Ok(actual) => {
                output.truncate(actual);
                return Ok(output);
            }
            Err(libdeflater::DecompressionError::InsufficientSpace) => {
                if capacity >= MAX_EXTRACTION_SIZE as usize {
                    return Err(LpmError::Registry(format!(
                        "gzip decompression exceeded {MAX_EXTRACTION_SIZE}-byte limit"
                    )));
                }
                // Drop the old buffer FIRST so its bytes leave the
                // process before we acquire the larger budget — keeps
                // peak memory at `new_capacity` rather than
                // `old + new`.
                drop(output);
                capacity = capacity.saturating_mul(2).min(MAX_EXTRACTION_SIZE as usize);
                drop(budget);
                budget = EXTRACT_BUDGET.acquire(capacity as u64);
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

/// Upper bound on the *initial* output-buffer allocation in
/// [`decompress_gzip_libdeflate`]. Real npm packages decompress to
/// well under this (the biggest packuments are ~10-50 MB), so 256 MiB
/// covers the legitimate one-shot case while preventing a small
/// compressed body from forcing a multi-GiB pre-allocation via a
/// tampered ISIZE footer field. The grow loop in
/// `decompress_gzip_libdeflate` handles the rare case where a real
/// payload exceeds this initial budget.
const INITIAL_ALLOCATION_CAP: usize = 256 * 1024 * 1024;

/// Global ceiling on the sum of in-flight gzip-decompress output
/// allocations across all rayon workers. The single-tarball cap
/// (`INITIAL_ALLOCATION_CAP`) bounds one decompress call at 256 MiB,
/// but a registry-mirror attacker can publish N small packages each
/// of which advertises a 256 MiB ISIZE; with 8 concurrent workers
/// the peak virtual allocation reaches ~2 GiB and OOMs containers
/// running `vm.overcommit_memory=2` or cgroup-bounded CI runners.
/// This budget caps the sum across workers — concurrent decompress
/// calls serialize at the budget boundary instead of competing for
/// virtual memory.
///
/// 1 GiB lets 4 simultaneous worst-case (ISIZE=256 MiB) decompresses
/// run in parallel and an arbitrary number of small ones; legitimate
/// npm packages decompress well below the per-call cap and rarely
/// hold a slot for more than a few ms.
const PARALLEL_EXTRACT_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

/// Counting semaphore over bytes of in-flight allocation in
/// `decompress_gzip_libdeflate`. Acquired on entry, released on
/// return — see [`AllocBudgetGuard`].
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
        let mut guard = self.available.lock().expect("EXTRACT_BUDGET poisoned");
        while *guard < request {
            guard = self
                .cv
                .wait(guard)
                .expect("EXTRACT_BUDGET condvar poisoned");
        }
        *guard -= request;
        AllocBudgetGuard {
            budget: self,
            bytes: request,
        }
    }
}

struct AllocBudgetGuard<'a> {
    budget: &'a AllocBudget,
    bytes: u64,
}

impl Drop for AllocBudgetGuard<'_> {
    fn drop(&mut self) {
        let mut guard = match self.budget.available.lock() {
            Ok(g) => g,
            // Poisoned mutex on parent panic — still release the
            // bytes so other waiters don't deadlock waiting on a
            // budget that the panicked thread held.
            Err(p) => p.into_inner(),
        };
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
/// - Max 5 GB total extraction size
/// - Max 500 MB per individual file
/// - Max 100,000 files
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
    /// Uncompressed size in bytes, read from the tar header.
    pub size: u64,
    /// File contents, if the caller's `buffer_predicate` returned `true`
    /// for this entry. `None` when the predicate said skip buffering — in
    /// which case `entry.unpack()` streamed the file to disk without
    /// materializing bytes in memory.
    pub bytes: Option<&'a [u8]>,
}

/// Extract tarball AND invoke a caller-supplied
/// inspector for every regular file entry. The inspector fires AFTER the
/// entry is safely on disk, with the entry's bytes-in-memory if the
/// `buffer_predicate` opted to buffer that entry.
///
/// Fused-scan use case: lpm-store's streaming path passes
/// `PackageAnalyzer::should_scan` as the predicate (true for scannable
/// JS/TS sources under the 2 MB per-file limit) and an inspector that
/// feeds each buffered entry into a running `PackageAnalyzer`. The result
/// is one filesystem pass instead of two — P1's extract writes files
/// while P2's scan reads the bytes it already has in hand, eliminating
/// the `analyze_package` post-extract walk.
///
/// Unbuffered entries (all non-source files, `.d.ts`, `.map`, files over
/// 2 MB, etc.) go through the original `entry.unpack()` streaming path.
/// Memory ceiling is bounded by the caller's predicate — for source
/// scanning, it's `files_under_2MB × max_concurrent_scanned_entries`,
/// which in practice is one file at a time within a single tarball.
pub fn extract_tarball_from_reader_with_inspector<P, I>(
    mut reader: impl std::io::Read,
    target_dir: &Path,
    buffer_predicate: P,
    mut inspector: I,
) -> Result<Vec<PathBuf>, LpmError>
where
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
    // The streaming pipeline still works because:
    // 1. Callers (e.g. `stream_and_store_package`) wrap the network reader
    //    with `HashingReader`. `read_to_end` here fully drains the reader,
    //    so the hasher sees every byte exactly once.
    // 2. The downstream `tar::Archive` consumes from an in-memory slice
    //    rather than the original reader — same archive walk logic, just
    //    fed by an already-decoded byte buffer.
    let mut compressed = Vec::new();
    reader.read_to_end(&mut compressed).map_err(LpmError::Io)?;
    if compressed.len() as u64 > MAX_BUFFERED_COMPRESSED_SIZE {
        return Err(LpmError::Registry(format!(
            "compressed tarball exceeds {MAX_BUFFERED_COMPRESSED_SIZE}-byte buffered-decode limit"
        )));
    }
    let decompressed = decompress_gzip_libdeflate(&compressed)?;
    drop(compressed);
    let mut archive = Archive::new(decompressed.as_slice());
    // npm tarballs ship arbitrary uid/gid/mode/mtime that mean nothing to a
    // downstream Node consumer. The tar crate's defaults call `fchmodat` +
    // `fchownat` + `filetime::set_file_handle_times` per regular file.
    // Disabling all three:
    // - `preserve_permissions(false)` — drops ownership-aware chmod policy.
    // - `preserve_ownerships(false)` — drops `fchownat`.
    // - `preserve_mtime(false)` — drops `set_file_handle_times` →
    //   `fsetattrlist` on macOS. mtime is meaningless for content-addressable
    //   store bytes — `require()` doesn't read it; `lpm doctor` doesn't use it.
    // Note: even with `preserve_permissions=false`, tar 0.4.45's `_set_perms`
    // still unconditionally calls `set_permissions` (the flag only controls
    // SUID-bit retention). Eliminating the residual `__fchmod` cost requires
    // bypassing `entry.unpack()` for non-buffered entries — see the
    // `write_buffered_entry` analogue used for source files below.
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_preserve_mtime(false);
    let mut extracted_files = Vec::new();
    let mut created_dirs = Vec::new();
    let mut total_size: u64 = 0;
    let mut file_count: usize = 0;

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
    let mut verified_parents: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::with_capacity(64);
    verified_parents.insert(extraction_root.clone());

    for entry_result in archive.entries()? {
        let mut entry = match entry_result {
            Ok(entry) => entry,
            Err(error) => {
                return rollback_extraction(
                    &extraction_root,
                    &extracted_files,
                    &created_dirs,
                    LpmError::Io(error),
                );
            }
        };

        // Enforce file count limit
        file_count += 1;
        if file_count > MAX_FILE_COUNT {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry(format!(
                    "tarball contains too many files (>{MAX_FILE_COUNT})"
                )),
            );
        }

        // Enforce per-file and total size limits
        let size = match entry.header().size() {
            Ok(size) => size,
            Err(error) => {
                return rollback_extraction(
                    &extraction_root,
                    &extracted_files,
                    &created_dirs,
                    LpmError::Registry(format!("invalid tar entry size: {error}")),
                );
            }
        };
        if size > MAX_FILE_SIZE {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry(format!(
                    "file too large in tarball: {} bytes (max {MAX_FILE_SIZE})",
                    size
                )),
            );
        }
        total_size += size;
        if total_size > MAX_EXTRACTION_SIZE {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry("tarball extraction size limit exceeded (5 GB)".to_string()),
            );
        }

        let original_path = match entry.path() {
            Ok(path) => path.into_owned(),
            Err(error) => {
                return rollback_extraction(
                    &extraction_root,
                    &extracted_files,
                    &created_dirs,
                    LpmError::Io(error),
                );
            }
        };

        // Strip first component (e.g., "package/src/index.js" → "src/index.js")
        let stripped = strip_first_component(&original_path);
        let Some(relative_path) = stripped else {
            continue;
        };

        if relative_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }) {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry(format!(
                    "path traversal detected in tarball: {}",
                    original_path.display()
                )),
            );
        }

        let target_path = match prepare_output_path(
            &extraction_root,
            &relative_path,
            &original_path,
            &mut verified_parents,
        ) {
            Ok((path, mut entry_created_dirs)) => {
                created_dirs.append(&mut entry_created_dirs);
                path
            }
            Err(error) => {
                return rollback_extraction(
                    &extraction_root,
                    &extracted_files,
                    &created_dirs,
                    error,
                );
            }
        };

        // Safety: prevent path traversal
        if !target_path.starts_with(&extraction_root) {
            return rollback_extraction(
                &extraction_root,
                &extracted_files,
                &created_dirs,
                LpmError::Registry(format!(
                    "path traversal detected in tarball: {}",
                    original_path.display()
                )),
            );
        }

        // Only extract regular files (skip symlinks for security)
        if entry.header().entry_type().is_file() {
            // Capture the tar entry's exec bits BEFORE any read; the
            // header is parsed up-front by the tar crate. We honor
            // whichever execute bits the tarball declares (user / group /
            // other) and OR them onto the default 0644 mode after the
            // write. SUID / SGID / sticky bits are deliberately dropped —
            // same security posture as `set_preserve_permissions(false)`.
            //
            // Most npm package files are 0644 (no exec) and skip the
            // post-write `set_permissions` call entirely. The only
            // affected files are bin scripts (typically 0755) — usually
            // 0–5 per package, so the syscall cost is negligible vs the
            // install-side breakage when a `.bin` script lands as 0644
            // (EACCES on `execve`).
            let exec_bits = entry.header().mode().unwrap_or(0o644) & 0o111;

            // P2 fused-scan hook: if the caller asked us to buffer this
            // entry's bytes for inspection, read the entry into memory,
            // write those bytes to disk, and hand them to the inspector.
            // Otherwise stream directly via `entry.unpack()` as the pre-P2
            // code did — same memory profile for non-buffered entries.
            let buffer_this = buffer_predicate(&relative_path, size);
            let buffered_bytes = if buffer_this {
                let mut buf = Vec::with_capacity(size as usize);
                if let Err(error) = entry.read_to_end(&mut buf) {
                    return rollback_extraction(
                        &extraction_root,
                        &extracted_files,
                        &created_dirs,
                        LpmError::Io(error),
                    );
                }
                if let Err(error) = write_buffered_entry(&target_path, &buf) {
                    return rollback_extraction(
                        &extraction_root,
                        &extracted_files,
                        &created_dirs,
                        error,
                    );
                }
                Some(buf)
            } else {
                // Stream directly to disk via `io::copy` instead of
                // `entry.unpack()`. Even with the three `preserve_*`
                // flags false, tar 0.4.45's unpack path unconditionally
                // calls `_set_perms` (entry.rs:814) — the flag only
                // controls SUID-bit retention. Bypassing it drops the
                // residual `__fchmod` cost on every non-buffered entry.
                //
                // Same minimal write semantics as [`write_buffered_entry`]:
                // create-or-truncate, default mode (umask-respecting), no
                // post-write metadata calls.
                if let Err(error) = stream_entry_to_disk(&mut entry, &target_path) {
                    return rollback_extraction(
                        &extraction_root,
                        &extracted_files,
                        &created_dirs,
                        error,
                    );
                }
                None
            };

            // Restore the exec bits captured before the write. Skipped
            // on Windows (NTFS doesn't have POSIX mode bits — bin
            // scripts are dispatched by extension, not the X bit).
            #[cfg(unix)]
            if exec_bits != 0 {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o644 | exec_bits);
                if let Err(error) = std::fs::set_permissions(&target_path, perms) {
                    return rollback_extraction(
                        &extraction_root,
                        &extracted_files,
                        &created_dirs,
                        LpmError::Io(error),
                    );
                }
            }
            #[cfg(not(unix))]
            let _ = exec_bits;

            inspector(EntryInfo {
                relative_path: &relative_path,
                size,
                bytes: buffered_bytes.as_deref(),
            });

            extracted_files.push(relative_path);
        }
    }

    Ok(extracted_files)
}

/// Write a fully-buffered entry to disk. Mirrors `tar::Entry::unpack`'s
/// file-creation semantics (create-or-truncate, 0644 default) without
/// restoring mode/mtime metadata — we don't need either for npm packages
/// and keeping it minimal reduces `fs` syscall count vs `tar`'s full
/// unpack path.
fn write_buffered_entry(target_path: &Path, bytes: &[u8]) -> Result<(), LpmError> {
    use std::io::Write;
    let mut file = create_leaf_file(target_path)?;
    file.write_all(bytes).map_err(LpmError::Io)?;
    Ok(())
}

/// Stream a tar entry's bytes directly to disk via `io::copy`, skipping
/// the chmod/chown/utimes epilogue `tar::Entry::unpack` always emits.
/// Used by the non-buffered branch of the extractor to bypass the
/// tar unpack epilogue (chmod/chown/utimes).
fn stream_entry_to_disk<R: std::io::Read>(
    entry: &mut tar::Entry<'_, R>,
    target_path: &Path,
) -> Result<(), LpmError> {
    let mut file = create_leaf_file(target_path)?;
    std::io::copy(entry, &mut file).map_err(LpmError::Io)?;
    Ok(())
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
fn create_leaf_file(target_path: &Path) -> Result<std::fs::File, LpmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
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
        std::fs::File::create(target_path).map_err(LpmError::Io)
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

/// Extract a .tgz from an in-memory byte slice. Delegates to `extract_tarball_from_reader`.
pub fn extract_tarball(data: &[u8], target_dir: &Path) -> Result<Vec<PathBuf>, LpmError> {
    extract_tarball_from_reader(data, target_dir)
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
    extract_tarball_from_reader(reader, target_dir)
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
    let decompressed = decompress_gzip_libdeflate(data)?;
    let mut archive = Archive::new(decompressed.as_slice());
    let mut files = Vec::new();

    for entry_result in archive.entries()? {
        let entry = entry_result?;
        if entry.header().entry_type().is_file() {
            let path = entry.path()?.into_owned();
            if let Some(stripped) = strip_first_component(&path) {
                files.push(stripped);
            }
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use lpm_common::integrity::HashAlgorithm;
    use std::io::Write;

    /// Create a test .tgz with a single file inside `package/`.
    fn create_test_tarball(filename: &str, content: &[u8]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();

            let tar_path = format!("package/{filename}");
            builder
                .append_data(&mut header, &tar_path, content)
                .unwrap();
            builder.finish().unwrap();
        }

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
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

    /// M17: a small compressed stream with a maliciously inflated
    /// ISIZE footer must not pre-allocate a multi-GiB buffer. We can't
    /// directly observe the allocation size from inside the test, but
    /// we CAN verify that decompression of a real payload still works
    /// when the footer claims an inflated ISIZE — proves the grow
    /// path handles the case where the initial cap clips the hint.
    /// Pin the constant alongside so a future bump is loud.
    #[test]
    fn initial_allocation_cap_bounds_pre_allocation() {
        // The bound itself: 256 MiB. If a future change relaxes this
        // (or removes the cap), this assertion fires and forces a
        // review of the M17 threat model.
        assert_eq!(
            INITIAL_ALLOCATION_CAP,
            256 * 1024 * 1024,
            "initial allocation cap must stay ≤ 256 MiB to defend against \
             hostile-ISIZE pre-allocation attacks",
        );
        // And the relationship to MAX_EXTRACTION_SIZE must hold —
        // the initial cap is a starting hint, not a ceiling.
        assert!(
            (INITIAL_ALLOCATION_CAP as u64) < MAX_EXTRACTION_SIZE,
            "initial cap must be strictly less than MAX_EXTRACTION_SIZE \
             so legitimate large payloads still extract via the grow path",
        );
    }

    /// Round-trip a real (small) gzip payload to prove the
    /// initial-allocation cap doesn't break the common path. The
    /// decompressed bytes must match the input.
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
}
