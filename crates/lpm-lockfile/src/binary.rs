//! Binary lockfile format (`lpm.lockb`) for generated cache validation.
//!
//! Layout (v3):
//! ```text
//! [Header: 16 bytes]
//!   magic:              [u8; 4]  = b"LPMB"
//!   version:            u32 LE   = 3
//!   package_count:      u32 LE
//!   string_table_off:   u32 LE   — byte offset where string table starts
//!
//! [PackageEntry × N: 36 bytes each]
//!   name_off:           u32 LE   — offset into string table
//!   name_len:           u16 LE
//!   version_off:        u32 LE
//!   version_len:        u16 LE
//!   source_off:         u32 LE   — 0 means None
//!   source_len:         u16 LE
//!   integrity_off:      u32 LE   — 0 means None
//!   integrity_len:      u16 LE
//!   deps_off:           u32 LE   — offset into deps table
//!   deps_count:         u16 LE
//!   tarball_off:        u32 LE   — 0 means None (v2+)
//!   tarball_len:        u16 LE
//!
//! [DepsEntry × total_deps: 6 bytes each]
//!   str_off:            u32 LE   — offset into string table
//!   str_len:            u16 LE
//!
//! [ProvenanceEntry × M: 68 bytes each] (v3+; sparse)
//!   package_index:       u32 LE
//!   evidence:            8 × (u32 offset, u16 length)
//!   integrated_time:     u64 LE
//!   rekor_log_index:     i64 LE
//!
//! [ProvenanceFooter: 8 bytes] (v3+)
//!   magic:               [u8; 4] = b"PRV3"
//!   evidence_count:      u32 LE
//!
//! [String table: packed UTF-8]
//! ```
//!
//! Entries are sorted by name (same as TOML lockfile) for binary search.
//!
//! ## Version compatibility
//!
//! The reader rejects any file whose header `version` is not exactly
//! [`BINARY_VERSION`]. This is strict because the per-entry layout
//! differs across versions — a v2 reader decoding v1 30-byte entries
//! as 36-byte entries would read package N's `name_off`/`name_len`
//! as package N-1's (nonexistent) tarball pair and produce garbage.
//! On rejection, install writeback rewrites `lpm.lockb` as the
//! current version. `Lockfile::read_fast` reads the TOML lockfile
//! directly so an opaque committed binary cache cannot override the
//! human-readable source.
//!
//! ## Null vs empty strings for optional fields
//!
//! Optional fields (`source`, `integrity`, `tarball`) use the
//! sentinel `(off=0, len=0)` to mean `None`. Because
//! `StringTable::insert("")` on the first insert would ALSO produce
//! `(0, 0)` — both `data.len() == 0` and `len == 0` — the writer
//! rejects empty strings at insert time to keep the sentinel
//! unambiguous. An empty tarball URL, integrity hash, or source is
//! nonsensical input regardless; failing loud is correct.

use crate::{LockedPackage, Lockfile, LockfileError};
use std::path::Path;

const MAGIC: &[u8; 4] = b"LPMB";
const PROVENANCE_MAGIC: &[u8; 4] = b"PRV3";
/// Binary lockfile wire-format version. v3 adds a sparse artifact-bound
/// provenance section. `pub` so
/// install writeback can report the generated binary format version.
pub const BINARY_VERSION: u32 = 3;
const HEADER_SIZE: usize = 16;
/// v3 keeps the v2 per-package layout so packages without provenance
/// pay no per-entry size penalty.
const ENTRY_SIZE: usize = 36;
const DEP_ENTRY_SIZE: usize = 6;
const PROVENANCE_ENTRY_SIZE: usize = 68;
const PROVENANCE_FOOTER_SIZE: usize = 8;

/// Binary lockfile filename.
pub const BINARY_LOCKFILE_NAME: &str = "lpm.lockb";

/// Little-endian `u32` read from a 4-byte window. `bytes[off..off+4]`
/// is the caller's invariant — every call site bounds-checks `off`
/// against the mmap length before reaching this helper, so the
/// fixed-size conversion cannot fail.
#[inline]
fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    let chunk: [u8; 4] = bytes[off..off + 4]
        .try_into()
        .expect("read_u32_le: caller validated 4-byte window");
    u32::from_le_bytes(chunk)
}

/// Little-endian `u16` read from a 2-byte window. See [`read_u32_le`]
/// for the bounds invariant.
#[inline]
fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    let chunk: [u8; 2] = bytes[off..off + 2]
        .try_into()
        .expect("read_u16_le: caller validated 2-byte window");
    u16::from_le_bytes(chunk)
}

#[inline]
fn read_u64_le(bytes: &[u8], off: usize) -> u64 {
    let chunk: [u8; 8] = bytes[off..off + 8]
        .try_into()
        .expect("read_u64_le: caller validated 8-byte window");
    u64::from_le_bytes(chunk)
}

#[inline]
fn read_i64_le(bytes: &[u8], off: usize) -> i64 {
    let chunk: [u8; 8] = bytes[off..off + 8]
        .try_into()
        .expect("read_i64_le: caller validated 8-byte window");
    i64::from_le_bytes(chunk)
}

// ── Writer ──────────────────────────────────────────────────────────────────

/// Binary format capability check — does this lockfile fit the wire format?
///
/// Does this lockfile fit the binary wire format? The binary format
/// has no section for TOML-only metadata such as patch, alias, peer,
/// platform, catalog, or registry-signature state. Writing those
/// lockfiles as binary would silently drop data and make the generated
/// companion disagree with the human-readable TOML lockfile. The
/// install writer MUST check this before calling `to_binary` and skip
/// the binary write when unsupported metadata is present.
///
/// Returns `true` for lockfiles whose metadata fits the current binary
/// slots; `false` the moment any TOML-only field is populated.
pub fn binary_format_supports(lockfile: &Lockfile) -> bool {
    if lockfile.metadata.lockfile_version >= crate::LOCKFILE_VERSION_WITH_PACKAGE_INSTANCES {
        return false;
    }
    if !lockfile.importers.is_empty() {
        return false;
    }
    if !lockfile.patches.is_empty() {
        return false;
    }
    if !lockfile.root_aliases.is_empty() {
        return false;
    }
    if !lockfile.root_resolutions.is_empty() {
        return false;
    }
    // Extend the same "skip binary fast path when the lockfile carries
    // metadata the binary schema can't encode" gate to peer fields.
    // Both `Lockfile.ambient_peer_installs` and per-package
    // `LockedPackage.peers` lack binary-format slots. Falling back to
    // TOML-only is the same conservative move we make for npm-aliases
    // — projects without any auto-installed peers AND no per-package
    // peer pinning still take the fast binary path.
    if !lockfile.ambient_peer_installs.is_empty() {
        return false;
    }
    if lockfile.metadata.auto_isolated_peer_conflicts {
        return false;
    }
    if !lockfile.catalogs.is_empty() {
        return false;
    }
    lockfile.packages.iter().all(|p| {
        p.alias_dependencies.is_empty()
            && p.peers.is_empty()
            && p.peer_edges.is_empty()
            && p.os.is_empty()
            && p.cpu.is_empty()
            && p.libc.is_empty()
            && p.node_engine.is_none()
            && p.manifest_fingerprint.is_none()
            && p.unpacked_size.is_none()
            && !p.optional
            && p.registry_signatures.is_empty()
            && p.registry_published_at.is_none()
    })
}

/// Serialize a `Lockfile` into the binary format.
///
/// Returns `LockfileError::Serialize` when the lockfile contains
/// alias or peer metadata. Callers should gate on
/// [`binary_format_supports`] and fall back to TOML-only when the
/// check fails.
pub fn to_binary(lockfile: &Lockfile) -> Result<Vec<u8>, LockfileError> {
    if !binary_format_supports(lockfile) {
        return Err(LockfileError::Serialize(
            "binary lockfile format cannot represent TOML-only metadata; \
             writer must fall back to TOML-only output"
                .to_string(),
        ));
    }
    Lockfile::validate_loaded_packages(&lockfile.packages)?;
    lockfile
        .validate_provenance()
        .map_err(LockfileError::Serialize)?;

    let mut strings = StringTable::new();
    let mut dep_entries: Vec<(u32, u16)> = Vec::new();

    // Pre-register all strings and collect dep info
    struct PkgInfo {
        name: (u32, u16),
        version: (u32, u16),
        source: (u32, u16),
        integrity: (u32, u16),
        deps_off: u32,
        deps_count: u16,
        /// v2+ — `(0, 0)` sentinel for None. Populated from
        /// `LockedPackage.tarball` via `insert_optional`, which
        /// rejects empty strings to keep the sentinel unambiguous.
        tarball: (u32, u16),
    }

    struct ProvenanceInfo {
        package_index: u32,
        publisher: (u32, u16),
        workflow_path: (u32, u16),
        workflow_ref: (u32, u16),
        cert_sha256: (u32, u16),
        subject_name: (u32, u16),
        subject_sha512: (u32, u16),
        log_id: (u32, u16),
        bundle_sha256: (u32, u16),
        integrated_time_secs: u64,
        log_index: i64,
    }

    let mut pkg_infos = Vec::with_capacity(lockfile.packages.len());
    let mut provenance_infos = Vec::with_capacity(lockfile.provenance.len());

    if lockfile.packages.len() > u32::MAX as usize {
        return Err(LockfileError::Serialize(format!(
            "too many packages for binary lockfile (max {})",
            u32::MAX
        )));
    }

    for (package_index, pkg) in lockfile.packages.iter().enumerate() {
        let name = strings.insert(&pkg.name)?;
        let version = strings.insert(&pkg.version)?;
        let source = insert_optional(&mut strings, pkg.source.as_deref(), "source", &pkg.name)?;
        let integrity = insert_optional(
            &mut strings,
            pkg.integrity.as_deref(),
            "integrity",
            &pkg.name,
        )?;
        let tarball = insert_optional(&mut strings, pkg.tarball.as_deref(), "tarball", &pkg.name)?;
        if let Some(evidence) = lockfile.verified_provenance(&pkg.package_key()) {
            provenance_infos.push(ProvenanceInfo {
                package_index: package_index as u32,
                publisher: insert_optional(
                    &mut strings,
                    evidence.snapshot.publisher.as_deref(),
                    "provenance publisher",
                    &pkg.name,
                )?,
                workflow_path: insert_optional(
                    &mut strings,
                    evidence.snapshot.workflow_path.as_deref(),
                    "provenance workflow path",
                    &pkg.name,
                )?,
                workflow_ref: insert_optional(
                    &mut strings,
                    evidence.snapshot.workflow_ref.as_deref(),
                    "provenance workflow ref",
                    &pkg.name,
                )?,
                cert_sha256: insert_optional(
                    &mut strings,
                    evidence.snapshot.attestation_cert_sha256.as_deref(),
                    "provenance certificate digest",
                    &pkg.name,
                )?,
                subject_name: strings.insert(&evidence.subject_name)?,
                subject_sha512: strings.insert(&evidence.subject_sha512)?,
                log_id: strings.insert(&evidence.log_id)?,
                bundle_sha256: strings.insert(&evidence.bundle_sha256)?,
                integrated_time_secs: evidence.integrated_time_secs,
                log_index: evidence.log_index,
            });
        }

        let new_total = dep_entries.len() + pkg.dependencies.len();
        if new_total > u32::MAX as usize {
            return Err(LockfileError::Serialize(format!(
                "too many total dependencies for binary lockfile ({} would exceed max {})",
                new_total,
                u32::MAX
            )));
        }
        let deps_off = dep_entries.len() as u32;

        if pkg.dependencies.len() > u16::MAX as usize {
            return Err(LockfileError::Serialize(format!(
                "package '{}' has too many dependencies for binary lockfile (max {})",
                pkg.name,
                u16::MAX
            )));
        }
        let deps_count = pkg.dependencies.len() as u16;

        for dep in &pkg.dependencies {
            dep_entries.push(strings.insert(dep)?);
        }

        pkg_infos.push(PkgInfo {
            name,
            version,
            source,
            integrity,
            deps_off,
            deps_count,
            tarball,
        });
    }

    let pkg_count = lockfile.packages.len();
    let deps_section_offset = HEADER_SIZE + pkg_count * ENTRY_SIZE;
    let provenance_section_offset = deps_section_offset + dep_entries.len() * DEP_ENTRY_SIZE;
    let provenance_entries_len = provenance_infos
        .len()
        .checked_mul(PROVENANCE_ENTRY_SIZE)
        .ok_or_else(|| {
            LockfileError::Serialize("provenance section size exceeds platform limits".to_string())
        })?;
    let string_table_offset = provenance_section_offset
        .checked_add(provenance_entries_len)
        .and_then(|offset| offset.checked_add(PROVENANCE_FOOTER_SIZE))
        .ok_or_else(|| {
            LockfileError::Serialize("binary lockfile section layout overflows".to_string())
        })?;
    if string_table_offset > u32::MAX as usize {
        return Err(LockfileError::Serialize(
            "binary lockfile section layout exceeds 32-bit offsets".to_string(),
        ));
    }
    if provenance_infos.len() > u32::MAX as usize {
        return Err(LockfileError::Serialize(
            "too many provenance entries for binary lockfile".to_string(),
        ));
    }

    let total_size = string_table_offset + strings.data.len();
    let mut buf = Vec::with_capacity(total_size);

    // Header
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&BINARY_VERSION.to_le_bytes());
    buf.extend_from_slice(&(pkg_count as u32).to_le_bytes());
    buf.extend_from_slice(&(string_table_offset as u32).to_le_bytes());

    // Package entries
    for info in &pkg_infos {
        buf.extend_from_slice(&info.name.0.to_le_bytes());
        buf.extend_from_slice(&info.name.1.to_le_bytes());
        buf.extend_from_slice(&info.version.0.to_le_bytes());
        buf.extend_from_slice(&info.version.1.to_le_bytes());
        buf.extend_from_slice(&info.source.0.to_le_bytes());
        buf.extend_from_slice(&info.source.1.to_le_bytes());
        buf.extend_from_slice(&info.integrity.0.to_le_bytes());
        buf.extend_from_slice(&info.integrity.1.to_le_bytes());
        buf.extend_from_slice(&info.deps_off.to_le_bytes());
        buf.extend_from_slice(&info.deps_count.to_le_bytes());
        // v2+ — tarball URL slot.
        buf.extend_from_slice(&info.tarball.0.to_le_bytes());
        buf.extend_from_slice(&info.tarball.1.to_le_bytes());
    }

    // Deps entries
    for (off, len) in &dep_entries {
        buf.extend_from_slice(&off.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
    }

    for provenance in &provenance_infos {
        buf.extend_from_slice(&provenance.package_index.to_le_bytes());
        for (off, len) in [
            provenance.publisher,
            provenance.workflow_path,
            provenance.workflow_ref,
            provenance.cert_sha256,
            provenance.subject_name,
            provenance.subject_sha512,
            provenance.log_id,
            provenance.bundle_sha256,
        ] {
            buf.extend_from_slice(&off.to_le_bytes());
            buf.extend_from_slice(&len.to_le_bytes());
        }
        buf.extend_from_slice(&provenance.integrated_time_secs.to_le_bytes());
        buf.extend_from_slice(&provenance.log_index.to_le_bytes());
    }
    buf.extend_from_slice(PROVENANCE_MAGIC);
    buf.extend_from_slice(&(provenance_infos.len() as u32).to_le_bytes());

    // String table
    buf.extend_from_slice(&strings.data);

    debug_assert_eq!(buf.len(), total_size);
    Ok(buf)
}

/// Write binary lockfile to disk atomically.
pub fn write_binary(lockfile: &Lockfile, path: &Path) -> Result<(), LockfileError> {
    let data = to_binary(lockfile)?;
    lpm_common::write_file_atomic(path, &data)
        .map_err(|e| LockfileError::Io(format!("failed to write {}: {e}", path.display())))
}

// ── Reader (mmap) ───────────────────────────────────────────────────────────

/// Memory-mapped binary lockfile reader. Zero-copy string access.
#[derive(Debug)]
pub struct BinaryLockfileReader {
    mmap: memmap2::Mmap,
}

impl BinaryLockfileReader {
    /// Open and mmap a binary lockfile. Returns None if file doesn't exist.
    pub fn open(path: &Path) -> Result<Option<Self>, LockfileError> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(LockfileError::Io(format!(
                    "failed to open {}: {error}",
                    path.display()
                )));
            }
        };
        let file_len = file
            .metadata()
            .map_err(|error| {
                LockfileError::Io(format!("failed to inspect {}: {error}", path.display()))
            })?
            .len();
        if file_len > crate::TOML_LOCKFILE_SIZE_CAP_BYTES {
            return Err(LockfileError::Deserialize(format!(
                "binary lockfile size {file_len} bytes exceeds limit of {} bytes",
                crate::TOML_LOCKFILE_SIZE_CAP_BYTES
            )));
        }
        let map_len = usize::try_from(file_len).map_err(|_| {
            LockfileError::Deserialize(format!(
                "binary lockfile size {file_len} bytes cannot be represented on this platform"
            ))
        })?;
        if map_len < HEADER_SIZE {
            return Err(LockfileError::Deserialize(
                "binary lockfile too small".into(),
            ));
        }

        // SAFETY: we only read the file, no concurrent writes expected during install
        let mmap = unsafe {
            memmap2::MmapOptions::new()
                .len(map_len)
                .map(&file)
                .map_err(|e| LockfileError::Io(format!("failed to mmap {}: {e}", path.display())))?
        };

        // Validate header
        if &mmap[0..4] != MAGIC {
            return Err(LockfileError::Deserialize(
                "invalid binary lockfile magic".into(),
            ));
        }
        let version = read_u32_le(&mmap, 4);
        // Strict version match — not `version > BINARY_VERSION`.
        // Per-entry layout differs across versions (v1 = 30B,
        // v2/v3 = 36B), and v3 adds a sparse section plus footer.
        // Decoding under the wrong version produces garbage.
        // `read_fast` catches this error and falls through to TOML;
        // the next `write_all` rewrites `lpm.lockb` at the current
        // version, completing the migration transparently.
        if version != BINARY_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                found: version,
                max_supported: BINARY_VERSION,
            });
        }

        // Validate section layout consistency
        let pkg_count = read_u32_le(&mmap, 8) as usize;
        let string_table_off = read_u32_le(&mmap, 12) as usize;

        let entries_end = pkg_count
            .checked_mul(ENTRY_SIZE)
            .and_then(|v| v.checked_add(HEADER_SIZE))
            .ok_or_else(|| {
                LockfileError::Deserialize("package count overflows section layout".into())
            })?;

        if entries_end > mmap.len() {
            return Err(LockfileError::Deserialize(
                "file too small for declared package count".into(),
            ));
        }
        if string_table_off > mmap.len() {
            return Err(LockfileError::Deserialize(
                "string table offset past end of file".into(),
            ));
        }
        if entries_end > string_table_off {
            return Err(LockfileError::Deserialize(
                "package entries overlap with string table".into(),
            ));
        }

        let footer_start = string_table_off
            .checked_sub(PROVENANCE_FOOTER_SIZE)
            .ok_or_else(|| {
                LockfileError::Deserialize("binary lockfile has no provenance footer".into())
            })?;
        if footer_start < entries_end {
            return Err(LockfileError::Deserialize(
                "package entries overlap with provenance footer".into(),
            ));
        }
        if &mmap[footer_start..footer_start + 4] != PROVENANCE_MAGIC {
            return Err(LockfileError::Deserialize(
                "invalid binary provenance footer magic".into(),
            ));
        }
        let provenance_count = read_u32_le(&mmap, footer_start + 4) as usize;
        let provenance_section_len = provenance_count
            .checked_mul(PROVENANCE_ENTRY_SIZE)
            .ok_or_else(|| {
                LockfileError::Deserialize("provenance entry count overflows layout".into())
            })?;
        let provenance_section_start = footer_start
            .checked_sub(provenance_section_len)
            .filter(|start| *start >= entries_end)
            .ok_or_else(|| {
                LockfileError::Deserialize(
                    "provenance section overlaps package entries or exceeds file".into(),
                )
            })?;

        let deps_section_len = provenance_section_start - entries_end;
        if !deps_section_len.is_multiple_of(DEP_ENTRY_SIZE) {
            return Err(LockfileError::Deserialize(
                "dependency table is not aligned to entry size".into(),
            ));
        }

        let total_dep_entries = deps_section_len / DEP_ENTRY_SIZE;
        // Strings section runs from string_table_off to EOF.
        let string_table_len = mmap.len() - string_table_off;
        std::str::from_utf8(&mmap[string_table_off..]).map_err(|error| {
            LockfileError::Deserialize(format!(
                "binary lockfile string table is not valid UTF-8: {error}"
            ))
        })?;
        for dependency_index in 0..total_dep_entries {
            let base = entries_end + dependency_index * DEP_ENTRY_SIZE;
            let off = read_u32_le(&mmap, base) as usize;
            let len = read_u16_le(&mmap, base + 4) as usize;
            if len == 0 {
                return Err(LockfileError::Deserialize(
                    "dependency string has zero length".into(),
                ));
            }
            let end = off.checked_add(len).ok_or_else(|| {
                LockfileError::Deserialize("dependency string range overflows string table".into())
            })?;
            if end > string_table_len {
                return Err(LockfileError::Deserialize(
                    "dependency string range extends past string table".into(),
                ));
            }
        }
        for idx in 0..pkg_count {
            let base = HEADER_SIZE + idx * ENTRY_SIZE;
            let deps_off = read_u32_le(&mmap, base + 24) as usize;
            let deps_count = read_u16_le(&mmap, base + 28) as usize;
            let deps_end = deps_off.checked_add(deps_count).ok_or_else(|| {
                LockfileError::Deserialize("dependency range overflows dependency table".into())
            })?;

            if deps_end > total_dep_entries {
                return Err(LockfileError::Deserialize(
                    "dependency range extends past dependency table".into(),
                ));
            }

            // Validate the tarball pair eagerly so a corrupted slot
            // forces TOML fallback instead of silently surfacing
            // `Some("")` (which `read_str` returns on out-of-bounds
            // or zero-length reads).
            //
            // Invariant: the ONLY legitimate zero-length slot is the
            // null sentinel `(off=0, len=0)`. A non-null pair must
            // have `len > 0` AND fit inside the string table. Reject:
            //   - `len == 0 && off != 0` — orphan offset (this
            //     case is not caught by `off + len > string_table_len`
            //     because `len == 0` makes that check trivially false).
            //   - `off + len` overflows or exceeds the string table.
            let tarball_off = read_u32_le(&mmap, base + 30) as usize;
            let tarball_len = read_u16_le(&mmap, base + 34) as usize;
            if !(tarball_off == 0 && tarball_len == 0) {
                if tarball_len == 0 {
                    // off != 0 && len == 0 — corrupt. Legitimate
                    // `None` uses `(0, 0)`; legitimate `Some(...)`
                    // has `len > 0`.
                    return Err(LockfileError::Deserialize(
                        "tarball slot has non-zero offset with zero length; \
                         only (0, 0) is a valid null sentinel"
                            .into(),
                    ));
                }
                let tarball_end = tarball_off.checked_add(tarball_len).ok_or_else(|| {
                    LockfileError::Deserialize("tarball range overflows string table".into())
                })?;
                if tarball_end > string_table_len {
                    return Err(LockfileError::Deserialize(
                        "tarball range extends past string table".into(),
                    ));
                }
            }

            // Eagerly validate name / version / source / integrity
            // ranges so a crafted `lpm.lockb` can't
            // silently surface `Some("")` for any of them via
            // `read_str`'s OOB fallback. Per the lockfile contract:
            //   - `name` / `version` MUST be non-empty (every
            //     package has identity) — these are load-bearing for
            //     install-graph correctness; the write path rejects
            //     empty strings here.
            //   - `source` / `integrity` MAY be empty (some source
            //     kinds — directory / link — don't carry integrity,
            //     and an empty source string serialises as the null
            //     sentinel) — only the range fit-in-string-table
            //     check applies.
            //
            // Either way, a corrupt (len=0 && off!=0) slot is
            // rejected since it indicates writer-side corruption: a
            // legitimate empty field uses (0, 0).
            for (field, off_range, len_range, len_must_be_nonzero) in [
                ("name", base..base + 4, base + 4..base + 6, true),
                ("version", base + 6..base + 10, base + 10..base + 12, true),
                ("source", base + 12..base + 16, base + 16..base + 18, false),
                (
                    "integrity",
                    base + 18..base + 22,
                    base + 22..base + 24,
                    false,
                ),
            ] {
                let off = read_u32_le(&mmap, off_range.start) as usize;
                let len = read_u16_le(&mmap, len_range.start) as usize;
                if len == 0 {
                    if off != 0 {
                        return Err(LockfileError::Deserialize(format!(
                            "package entry {field} has zero length with non-zero offset \
                             (corrupt — legitimate null uses (0, 0))"
                        )));
                    }
                    if len_must_be_nonzero {
                        return Err(LockfileError::Deserialize(format!(
                            "package entry has zero-length {field} field — \
                             every package must carry a non-empty {field}"
                        )));
                    }
                    continue;
                }
                let end = off.checked_add(len).ok_or_else(|| {
                    LockfileError::Deserialize(format!(
                        "package entry {field} range overflows string table"
                    ))
                })?;
                if end > string_table_len {
                    return Err(LockfileError::Deserialize(format!(
                        "package entry {field} range extends past string table"
                    )));
                }
            }
        }

        let mut previous_package_index = None;
        for record_index in 0..provenance_count {
            let base = provenance_section_start + record_index * PROVENANCE_ENTRY_SIZE;
            let package_index = read_u32_le(&mmap, base) as usize;
            if package_index >= pkg_count {
                return Err(LockfileError::Deserialize(
                    "provenance entry references a package outside the package table".into(),
                ));
            }
            if previous_package_index.is_some_and(|previous| package_index <= previous) {
                return Err(LockfileError::Deserialize(
                    "provenance entries must reference unique packages in ascending order".into(),
                ));
            }
            previous_package_index = Some(package_index);

            for (field, slot, required) in [
                ("provenance publisher", 4usize, false),
                ("provenance workflow path", 10, false),
                ("provenance workflow ref", 16, false),
                ("provenance certificate digest", 22, false),
                ("provenance subject name", 28, true),
                ("provenance subject sha512", 34, true),
                ("provenance log id", 40, true),
                ("provenance bundle sha256", 46, true),
            ] {
                let off = read_u32_le(&mmap, base + slot) as usize;
                let len = read_u16_le(&mmap, base + slot + 4) as usize;
                if len == 0 {
                    if off != 0 || required {
                        return Err(LockfileError::Deserialize(format!(
                            "provenance entry has invalid {field} slot"
                        )));
                    }
                    continue;
                }
                let end = off.checked_add(len).ok_or_else(|| {
                    LockfileError::Deserialize(format!("{field} range overflows string table"))
                })?;
                if end > string_table_len {
                    return Err(LockfileError::Deserialize(format!(
                        "{field} range extends past string table"
                    )));
                }
            }
        }

        Ok(Some(Self { mmap }))
    }

    fn pkg_count(&self) -> u32 {
        read_u32_le(&self.mmap, 8)
    }

    fn string_table_off(&self) -> usize {
        read_u32_le(&self.mmap, 12) as usize
    }

    fn provenance_count(&self) -> usize {
        read_u32_le(
            &self.mmap,
            self.string_table_off() - PROVENANCE_FOOTER_SIZE + 4,
        ) as usize
    }

    fn provenance_section_start(&self) -> usize {
        self.string_table_off()
            - PROVENANCE_FOOTER_SIZE
            - self.provenance_count() * PROVENANCE_ENTRY_SIZE
    }

    fn read_str(&self, off: u32, len: u16) -> &str {
        if len == 0 && off == 0 {
            return "";
        }
        let st_off = self.string_table_off();
        // off is relative to string_table_off, so start is always >= st_off
        // when checked_add succeeds. Overflow returns "" via the None branch.
        let start = match st_off.checked_add(off as usize) {
            Some(v) => v,
            None => return "",
        };
        let end = match start.checked_add(len as usize) {
            Some(v) => v,
            None => return "",
        };
        if end > self.mmap.len() {
            return "";
        }
        std::str::from_utf8(&self.mmap[start..end]).unwrap_or("")
    }

    fn entry_at(&self, idx: usize) -> Option<PackageEntryView<'_>> {
        if idx >= self.pkg_count() as usize {
            return None;
        }
        let offset = idx.checked_mul(ENTRY_SIZE)?;
        let base = HEADER_SIZE.checked_add(offset)?;
        let end = base.checked_add(ENTRY_SIZE)?;
        if end > self.mmap.len() {
            return None;
        }
        let b = &self.mmap[base..base + ENTRY_SIZE];
        Some(PackageEntryView {
            reader: self,
            name_off: read_u32_le(b, 0),
            name_len: read_u16_le(b, 4),
            version_off: read_u32_le(b, 6),
            version_len: read_u16_le(b, 10),
            source_off: read_u32_le(b, 12),
            source_len: read_u16_le(b, 16),
            integrity_off: read_u32_le(b, 18),
            integrity_len: read_u16_le(b, 22),
            deps_off: read_u32_le(b, 24),
            deps_count: read_u16_le(b, 28),
            // v2+ — tarball slot at bytes [30..36]. Parses cleanly on
            // every v2 file; the null sentinel (0, 0) decodes to `None`
            // in `tarball()`.
            tarball_off: read_u32_le(b, 30),
            tarball_len: read_u16_le(b, 34),
        })
    }

    fn provenance_at(&self, idx: usize) -> Option<(usize, crate::LockedProvenance)> {
        if idx >= self.provenance_count() {
            return None;
        }
        let base = self
            .provenance_section_start()
            .checked_add(idx.checked_mul(PROVENANCE_ENTRY_SIZE)?)?;
        let end = base.checked_add(PROVENANCE_ENTRY_SIZE)?;
        if end > self.string_table_off() {
            return None;
        }
        let bytes = &self.mmap[base..end];
        let slot = |offset| (read_u32_le(bytes, offset), read_u16_le(bytes, offset + 4));
        let optional_str = |value: (u32, u16)| {
            (value != (0, 0)).then(|| self.read_str(value.0, value.1).to_string())
        };
        let required_str =
            |offset| self.read_str(read_u32_le(bytes, offset), read_u16_le(bytes, offset + 4));

        Some((
            read_u32_le(bytes, 0) as usize,
            crate::LockedProvenance {
                snapshot: lpm_common::ProvenanceSnapshot {
                    present: true,
                    publisher: optional_str(slot(4)),
                    workflow_path: optional_str(slot(10)),
                    workflow_ref: optional_str(slot(16)),
                    attestation_cert_sha256: optional_str(slot(22)),
                },
                subject_name: required_str(28).to_string(),
                subject_sha512: required_str(34).to_string(),
                integrated_time_secs: read_u64_le(bytes, 52),
                log_id: required_str(40).to_string(),
                log_index: read_i64_le(bytes, 60),
                bundle_sha256: required_str(46).to_string(),
            },
        ))
    }

    /// Binary search for a package by name. O(log n), zero-copy.
    ///
    /// Name-only lookup. Under cross-source collision (a registry
    /// package and a tarball-URL package with the same
    /// `(name, version)` in one lockfile), this returns whichever
    /// entry the binary search lands on — effectively arbitrary.
    /// New code MUST prefer [`Self::find_package_by_key`], which
    /// keys on the full `(name, version, source_id)` triple. This
    /// name-only method is retained for callers where the lockfile
    /// is guaranteed registry-only and name uniquely identifies a
    /// package.
    pub fn find_package(&self, name: &str) -> Option<PackageEntryView<'_>> {
        let count = self.pkg_count() as usize;
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.entry_at(mid)?;
            match entry.name().cmp(name) {
                std::cmp::Ordering::Equal => return Some(entry),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Source-aware lookup keyed by the full `(name, version,
    /// source_id)` triple. Mirrors
    /// [`crate::Lockfile::find_package_by_key`] so the binary fast
    /// path has the same disambiguation guarantee as the TOML path.
    ///
    /// Binary entries are written in the same order the in-memory
    /// `Lockfile` sorts them — by `(name, version, source_id)` —
    /// so a triple-aware binary search lands on the exact match,
    /// or `None` if no entry has that key. Returns the requested
    /// side under cross-source collision, never an arbitrary shadow.
    ///
    /// O(log n) on the package count; each comparison parses the
    /// source string for `source_id` (16-hex SHA-256 truncate),
    /// which is the same per-comparison cost the TOML
    /// `find_package_by_key` pays.
    pub fn find_package_by_key(&self, key: &crate::PackageKey) -> Option<PackageEntryView<'_>> {
        let count = self.pkg_count() as usize;
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.entry_at(mid)?;
            let mid_key = entry.package_key();
            let ord = mid_key
                .name
                .as_str()
                .cmp(key.name.as_str())
                .then_with(|| mid_key.version.as_str().cmp(key.version.as_str()))
                .then_with(|| mid_key.source_id.as_str().cmp(key.source_id.as_str()));
            match ord {
                std::cmp::Ordering::Equal => return Some(entry),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Convert the binary lockfile back to a `Lockfile`. Metadata
    /// fields (resolved_with) aren't stored in the binary format and
    /// fall back to defaults; the TOML lockfile is the source of truth
    /// for metadata. Returns `Err` when entries violate cross-format
    /// invariants (currently `@lpm.dev/*` scope-pin) — `read_fast`
    /// falls back to the TOML form on this error.
    pub fn to_lockfile(&self) -> Result<Lockfile, LockfileError> {
        let count = self.pkg_count() as usize;
        let mut packages = Vec::with_capacity(count);
        for i in 0..count {
            if let Some(entry) = self.entry_at(i) {
                packages.push(entry.to_locked_package());
            }
        }
        crate::Lockfile::validate_loaded_packages(&packages)?;
        let mut provenance = std::collections::BTreeMap::new();
        for record_index in 0..self.provenance_count() {
            let (package_index, evidence) = self.provenance_at(record_index).ok_or_else(|| {
                LockfileError::Deserialize(
                    "validated provenance record could not be decoded".into(),
                )
            })?;
            provenance.insert(
                packages[package_index].package_key().lockfile_id(),
                evidence,
            );
        }
        let lockfile = Lockfile {
            metadata: crate::LockfileMetadata {
                lockfile_version: crate::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS,
                resolved_with: Some(crate::DEFAULT_RESOLVED_WITH.to_string()),
                auto_isolated_peer_conflicts: false,
            },
            importers: crate::ImporterSnapshots::new(),
            patches: crate::LockfilePatches::new(),
            catalogs: crate::CatalogSnapshots::new(),
            provenance,
            packages,
            workspace_packages: std::collections::BTreeMap::new(),
            // The binary format cannot represent alias metadata; any
            // project with aliases skips the binary write (see
            // `binary_format_supports`), so binary-backed reads always
            // correspond to an alias-free lockfile and this field is
            // always empty.
            root_aliases: std::collections::BTreeMap::new(),
            root_resolutions: crate::RootResolutions::new(),
            // Same reasoning as `root_aliases`: projects with ambient
            // peer installs skip the binary write entirely, so any
            // `to_lockfile()` we'd reach is for a binary-representable
            // lockfile, which by construction has no ambient peers.
            ambient_peer_installs: Vec::new(),
        };
        lockfile
            .validate_provenance()
            .map_err(LockfileError::Deserialize)?;
        Ok(lockfile)
    }

    /// Number of packages in the lockfile.
    pub fn package_count(&self) -> usize {
        self.pkg_count() as usize
    }

    /// Iterate all package entries.
    pub fn iter(&self) -> impl Iterator<Item = PackageEntryView<'_>> {
        let count = self.pkg_count() as usize;
        (0..count).filter_map(move |i| self.entry_at(i))
    }
}

/// Zero-copy view of a single package entry in the binary lockfile.
pub struct PackageEntryView<'a> {
    reader: &'a BinaryLockfileReader,
    name_off: u32,
    name_len: u16,
    version_off: u32,
    version_len: u16,
    source_off: u32,
    source_len: u16,
    integrity_off: u32,
    integrity_len: u16,
    deps_off: u32,
    deps_count: u16,
    /// v2+ — tarball URL slot. `(0, 0)` = None.
    tarball_off: u32,
    tarball_len: u16,
}

impl<'a> PackageEntryView<'a> {
    pub fn name(&self) -> &'a str {
        self.reader.read_str(self.name_off, self.name_len)
    }

    pub fn version(&self) -> &'a str {
        self.reader.read_str(self.version_off, self.version_len)
    }

    pub fn source(&self) -> Option<&'a str> {
        if self.source_len == 0 && self.source_off == 0 {
            None
        } else {
            Some(self.reader.read_str(self.source_off, self.source_len))
        }
    }

    pub fn integrity(&self) -> Option<&'a str> {
        if self.integrity_len == 0 && self.integrity_off == 0 {
            None
        } else {
            Some(self.reader.read_str(self.integrity_off, self.integrity_len))
        }
    }

    /// Tarball URL as stored by the resolver. Used by
    /// `try_lockfile_fast_path` to skip per-package metadata lookup
    /// on warm installs (gated by `evaluate_cached_url` for
    /// scheme/shape/origin safety).
    pub fn tarball(&self) -> Option<&'a str> {
        if self.tarball_len == 0 && self.tarball_off == 0 {
            None
        } else {
            Some(self.reader.read_str(self.tarball_off, self.tarball_len))
        }
    }

    pub fn dependencies(&self) -> Vec<&'a str> {
        let deps_section_start = HEADER_SIZE + self.reader.pkg_count() as usize * ENTRY_SIZE;
        let provenance_section_start = self.reader.provenance_section_start();
        let mmap_len = self.reader.mmap.len();
        let mut deps = Vec::with_capacity(self.deps_count as usize);
        for i in 0..self.deps_count as usize {
            let idx = match (self.deps_off as usize).checked_add(i) {
                Some(v) => v,
                None => break,
            };
            let offset = match idx.checked_mul(DEP_ENTRY_SIZE) {
                Some(v) => v,
                None => break,
            };
            let base = match deps_section_start.checked_add(offset) {
                Some(v) => v,
                None => break,
            };
            let base_end = match base.checked_add(DEP_ENTRY_SIZE) {
                Some(v) => v,
                None => break,
            };
            if base_end > provenance_section_start || base_end > mmap_len {
                break;
            }
            let b = &self.reader.mmap[base..base + DEP_ENTRY_SIZE];
            let off = read_u32_le(b, 0);
            let len = read_u16_le(b, 4);
            deps.push(self.reader.read_str(off, len));
        }
        deps
    }

    /// Three-tuple identity for this binary entry, mirroring
    /// [`LockedPackage::package_key`].
    ///
    /// Used by [`BinaryLockfileReader::find_package_by_key`] to
    /// disambiguate cross-source collisions without forcing a
    /// `to_locked_package` allocation per comparison.
    pub fn package_key(&self) -> crate::PackageKey {
        let source_id = match self.source().map(crate::Source::parse) {
            Some(Ok(s)) => s.source_id(),
            _ => crate::PackageKey::UNKNOWN_SOURCE_ID.to_string(),
        };
        crate::PackageKey::new(self.name(), self.version(), source_id)
    }

    /// Convert to owned `LockedPackage`.
    pub fn to_locked_package(&self) -> LockedPackage {
        LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: self.name().to_string(),
            version: self.version().to_string(),
            source: self.source().map(|s| s.to_string()),
            integrity: self.integrity().map(|s| s.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: self.dependencies().iter().map(|s| s.to_string()).collect(),
            // The binary format doesn't encode alias metadata;
            // callers needing alias round-trip must use the TOML
            // lockfile. The binary writer in `to_binary` detects
            // alias-bearing `Lockfile`s and refuses to write — the
            // warm-install path falls back to TOML. Adding an alias
            // section is the right follow-up, but the rarity of
            // aliased projects makes the TOML fallback a reasonable
            // interim trade-off.
            alias_dependencies: Vec::new(),
            // Same gate as alias_dependencies: per-package peers are
            // metadata the binary format doesn't encode. Projects with
            // peers fail `binary_format_supports` and fall back to TOML,
            // so any binary entry we round-trip here is by construction
            // peer-free.
            peers: Vec::new(),
            peer_edges: Vec::new(),
            // v2+ — read the tarball URL directly from the mmap via
            // the accessor; `None` when the slot is the `(0, 0)` null
            // sentinel.
            tarball: self.tarball().map(|s| s.to_string()),
        }
    }
}

/// Insert an optional string into the table, returning `(0, 0)` for
/// `None`. Rejects `Some("")` because it would collide with the null
/// sentinel on the first insert — empty strings are nonsensical
/// input for `source` / `integrity` / `tarball` anyway.
fn insert_optional(
    strings: &mut StringTable,
    value: Option<&str>,
    field_name: &'static str,
    pkg_name: &str,
) -> Result<(u32, u16), LockfileError> {
    match value {
        None => Ok((0, 0)),
        Some("") => Err(LockfileError::Serialize(format!(
            "package '{pkg_name}' has empty '{field_name}' — binary \
             lockfile cannot distinguish an empty string from `None` \
             (both would serialize as the `(0, 0)` sentinel). An empty \
             {field_name} is invalid; fix the source data."
        ))),
        Some(s) => strings.insert(s),
    }
}

// ── String Table Builder ────────────────────────────────────────────────────

struct StringTable {
    data: Vec<u8>,
    index: std::collections::HashMap<String, (u32, u16)>,
}

impl StringTable {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            index: std::collections::HashMap::new(),
        }
    }

    /// Insert a string with deduplication, returns (offset, length).
    fn insert(&mut self, s: &str) -> Result<(u32, u16), LockfileError> {
        if let Some(&cached) = self.index.get(s) {
            return Ok(cached);
        }
        if s.len() > u16::MAX as usize {
            return Err(LockfileError::Serialize(format!(
                "string too long for binary lockfile (len={}, max={}): {}...",
                s.len(),
                u16::MAX,
                &s[..64.min(s.len())]
            )));
        }
        if self.data.len() > u32::MAX as usize {
            return Err(LockfileError::Serialize(format!(
                "string table too large for binary lockfile (max {} bytes)",
                u32::MAX
            )));
        }
        let off = self.data.len() as u32;
        let len = s.len() as u16;
        self.data.extend_from_slice(s.as_bytes());
        self.index.insert(s.to_string(), (off, len));
        Ok((off, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LockedPackage, Lockfile};

    const VALID_SHA512_SRI: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const VALID_SHA512_SRI_ALT: &str = "sha512-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==";
    const VALID_SHA256_SRI: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn legacy_lockfile() -> Lockfile {
        let mut lockfile = Lockfile::new();
        lockfile.metadata.lockfile_version = crate::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
        lockfile
    }

    fn sample_lockfile() -> Lockfile {
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "@lpm.dev/neo.highlight".to_string(),
            version: "1.1.1".to_string(),
            source: Some("registry+https://lpm.dev".to_string()),
            integrity: Some(VALID_SHA512_SRI.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec!["react@18.2.0".to_string()],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "react".to_string(),
            version: "18.2.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lf
    }

    /// Helper: build a valid binary lockfile and return raw bytes
    fn sample_binary() -> Vec<u8> {
        to_binary(&sample_lockfile()).unwrap()
    }

    /// Helper: write bytes to a temp path and open with the reader.
    /// Returns the TempDir alongside the reader so it stays alive without leaking.
    fn open_bytes(
        bytes: &[u8],
    ) -> (
        tempfile::TempDir,
        Result<Option<BinaryLockfileReader>, LockfileError>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        std::fs::write(&path, bytes).unwrap();
        let result = BinaryLockfileReader::open(&path);
        (dir, result)
    }

    #[test]
    fn binary_roundtrip() {
        let lf = sample_lockfile();
        let binary = to_binary(&lf).unwrap();

        // Write and read back
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        std::fs::write(&path, &binary).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let restored = reader.to_lockfile().unwrap();

        assert_eq!(lf.packages.len(), restored.packages.len());
        for (orig, rest) in lf.packages.iter().zip(restored.packages.iter()) {
            assert_eq!(orig.name, rest.name);
            assert_eq!(orig.version, rest.version);
            assert_eq!(orig.source, rest.source);
            assert_eq!(orig.integrity, rest.integrity);
            assert_eq!(orig.dependencies, rest.dependencies);
        }
    }

    #[test]
    fn binary_find_package() {
        let lf = sample_lockfile();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();

        let react = reader.find_package("react").unwrap();
        assert_eq!(react.version(), "18.2.0");
        assert_eq!(react.source(), Some("registry+https://registry.npmjs.org"));
        assert!(react.dependencies().is_empty());

        let highlight = reader.find_package("@lpm.dev/neo.highlight").unwrap();
        assert_eq!(highlight.version(), "1.1.1");
        assert_eq!(highlight.dependencies(), vec!["react@18.2.0"]);
        assert_eq!(highlight.integrity(), Some(VALID_SHA512_SRI));

        assert!(reader.find_package("nonexistent").is_none());
    }

    // ── Cross-source collision in binary lockfile ──
    // The binary reader must offer the same source-aware disambiguation
    // guarantee as the TOML path. Without
    // `find_package_by_key`, a direct binary `find_package(name)`
    // call under a cross-source collision returns whichever entry
    // the binary search lands on — silently shadowing one side.

    fn cross_source_collision_lockfile() -> Lockfile {
        let mut lf = legacy_lockfile();
        // Registry react@19.0.0 (the upstream)
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some(VALID_SHA512_SRI.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec!["loose-envify@1.4.0".to_string()],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        // Tarball-URL react@19.0.0 (a fork bundling the same name+version)
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("tarball+https://example.com/react-fork-19.0.0.tgz".to_string()),
            integrity: Some(VALID_SHA512_SRI_ALT.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lf
    }

    #[test]
    fn binary_find_package_by_key_disambiguates_cross_source_collision() {
        let lf = cross_source_collision_lockfile();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        assert_eq!(reader.package_count(), 2, "both sides preserved");

        // Build the keys the install pipeline would produce.
        let registry_key = crate::PackageKey::new(
            "react",
            "19.0.0",
            crate::Source::Registry {
                url: "https://registry.npmjs.org".into(),
            }
            .source_id(),
        );
        let tarball_key = crate::PackageKey::new(
            "react",
            "19.0.0",
            crate::Source::Tarball {
                url: "https://example.com/react-fork-19.0.0.tgz".into(),
            }
            .source_id(),
        );

        let registry_entry = reader
            .find_package_by_key(&registry_key)
            .expect("registry side resolvable by key");
        assert_eq!(
            registry_entry.integrity(),
            Some(VALID_SHA512_SRI),
            "registry key must return the registry entry, not the fork"
        );

        let tarball_entry = reader
            .find_package_by_key(&tarball_key)
            .expect("tarball side resolvable by key");
        assert_eq!(
            tarball_entry.integrity(),
            Some(VALID_SHA512_SRI_ALT),
            "tarball key must return the fork, not the registry entry"
        );

        // Sanity: the two integrity values are actually distinct, so
        // the assertions above are meaningful.
        assert_ne!(
            registry_entry.integrity(),
            tarball_entry.integrity(),
            "fixture must encode distinct integrity for each side"
        );
    }

    #[test]
    fn binary_find_package_by_key_returns_none_on_miss() {
        let lf = cross_source_collision_lockfile();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();

        // Right name + version, different source URL → distinct
        // source_id → no match. Confirms the binary search doesn't
        // fall back to a name-only shadow under collision.
        let phantom_key = crate::PackageKey::new(
            "react",
            "19.0.0",
            crate::Source::Tarball {
                url: "https://other.example/react-19.0.0.tgz".into(),
            }
            .source_id(),
        );
        assert!(reader.find_package_by_key(&phantom_key).is_none());

        // Wrong name → no match.
        let absent_key = crate::PackageKey::new(
            "vue",
            "3.4.0",
            crate::Source::Registry {
                url: "https://registry.npmjs.org".into(),
            }
            .source_id(),
        );
        assert!(reader.find_package_by_key(&absent_key).is_none());
    }

    #[test]
    fn binary_find_package_by_key_matches_toml_find_package_by_key() {
        // Drift-lock: keep the binary lookup API aligned with the TOML
        // source-aware lookup even though command reads are TOML-authoritative.
        let lf = cross_source_collision_lockfile();
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("lpm.lockb");
        write_binary(&lf, &bin_path).unwrap();
        let reader = BinaryLockfileReader::open(&bin_path).unwrap().unwrap();

        for pkg in &lf.packages {
            let key = pkg.package_key();
            let bin_match = reader
                .find_package_by_key(&key)
                .map(|e| e.to_locked_package());
            let toml_match = lf.find_package_by_key(&key).cloned();
            assert_eq!(
                bin_match, toml_match,
                "binary and TOML find_package_by_key must agree for key {key:?}"
            );
        }
    }

    #[test]
    fn binary_header_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.lockb");

        // Too small
        std::fs::write(&path, b"LPM").unwrap();
        assert!(BinaryLockfileReader::open(&path).is_err());

        // Bad magic
        std::fs::write(&path, b"BADMxxxxxxxxxxxxxxxx").unwrap();
        assert!(BinaryLockfileReader::open(&path).is_err());

        // File doesn't exist
        let missing = dir.path().join("missing.lockb");
        assert!(BinaryLockfileReader::open(&missing).unwrap().is_none());
    }

    #[test]
    fn open_rejects_binary_lockfile_larger_than_the_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.lockb");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(crate::TOML_LOCKFILE_SIZE_CAP_BYTES + 1)
            .unwrap();

        let error = BinaryLockfileReader::open(&path)
            .expect_err("an oversized binary lockfile must be rejected before mapping");

        assert!(error.to_string().contains("exceeds limit"), "{error}");
    }

    #[test]
    fn binary_empty_lockfile() {
        let lf = legacy_lockfile();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        assert_eq!(reader.package_count(), 0);
        assert!(reader.find_package("anything").is_none());
    }

    #[test]
    fn binary_iter() {
        let lf = sample_lockfile();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let names: Vec<&str> = reader.iter().map(|e| e.name()).collect();
        assert_eq!(names, vec!["@lpm.dev/neo.highlight", "react"]);
    }

    #[test]
    fn binary_file_size_is_compact() {
        let lf = sample_lockfile();
        let binary = to_binary(&lf).unwrap();
        let toml = lf.to_toml().unwrap();

        // Binary should be smaller than TOML
        assert!(
            binary.len() < toml.len(),
            "binary {} bytes >= toml {} bytes",
            binary.len(),
            toml.len()
        );
    }

    #[test]
    fn write_binary_cleans_temporary_file_when_replacement_fails() {
        let lf = sample_lockfile();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("lpm.lockb");

        std::fs::create_dir(&target).unwrap();

        let result = write_binary(&lf, &target);

        assert!(result.is_err(), "replacement of a directory should fail");
        assert!(
            std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".lpm-")),
            "failed atomic write should clean its temporary file"
        );
    }

    // ── Corruption / bounds-check tests ─────────────────────────────────────

    /// M68: pre-fix `read_str` silently returned `""` on OOB offsets,
    /// letting a crafted `lpm.lockb` surface `Some("")` for a package
    /// name. `open()` now eagerly rejects the same corruption — the
    /// strict-at-open contract matches the TOML loader's behaviour
    /// for empty/missing identity fields.
    #[test]
    fn open_rejects_oob_name_offset() {
        let mut binary = sample_binary();
        let huge_off: u32 = 0xFFFF_FFFF;
        binary[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&huge_off.to_le_bytes());

        let (_dir, result) = open_bytes(&binary);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("name range") && (err.contains("overflows") || err.contains("past")),
            "error must name the bounds failure: {err}"
        );
    }

    #[test]
    fn open_rejects_invalid_utf8_in_string_table() {
        let mut binary = sample_binary();
        let string_table_off = read_u32_le(&binary, 12) as usize;
        let name_off = read_u32_le(&binary, HEADER_SIZE) as usize;
        binary[string_table_off + name_off] = 0xFF;

        let (_dir, result) = open_bytes(&binary);

        let error = result.expect_err("invalid UTF-8 must be rejected during open");
        assert!(error.to_string().contains("UTF-8"));
    }

    #[test]
    fn open_rejects_dependency_string_range_past_table() {
        let mut binary = sample_binary();
        let package_count = read_u32_le(&binary, 8) as usize;
        let dependency_entry = HEADER_SIZE + package_count * ENTRY_SIZE;
        binary[dependency_entry..dependency_entry + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        let (_dir, result) = open_bytes(&binary);

        let error = result.expect_err("dependency strings must be range-checked during open");
        assert!(error.to_string().contains("dependency string range"));
    }

    #[test]
    fn entry_at_oob_returns_none() {
        let binary = sample_binary();
        let (_dir, reader) = open_bytes(&binary);
        let reader = reader.unwrap().unwrap();
        // sample_lockfile has 2 packages; entry 99 must be None
        assert!(reader.entry_at(99).is_none());
        assert!(reader.entry_at(usize::MAX).is_none());
    }

    #[test]
    fn deps_oob_offset_returns_empty() {
        let mut binary = sample_binary();
        // Mutate the first entry's deps_off to a huge value
        // deps_off is at offset 24 within each entry
        let entry_base = HEADER_SIZE;
        let deps_off_pos = entry_base + 24;
        let huge_off: u32 = 0xFFFF_FFFF;
        binary[deps_off_pos..deps_off_pos + 4].copy_from_slice(&huge_off.to_le_bytes());
        // Also set deps_count to 5 so it tries to read
        let deps_count_pos = entry_base + 28;
        let count: u16 = 5;
        binary[deps_count_pos..deps_count_pos + 2].copy_from_slice(&count.to_le_bytes());

        let (_dir, reader) = open_bytes(&binary);
        let err = reader.unwrap_err();
        assert!(
            err.to_string()
                .contains("dependency range extends past dependency table"),
            "expected dependency range validation error, got: {err}"
        );
    }

    #[test]
    fn open_rejects_dependency_range_past_string_table() {
        let mut binary = sample_binary();
        let entry_base = HEADER_SIZE;
        let deps_count_pos = entry_base + 28;

        // sample_binary contains only 1 dependency entry total. Declaring 2
        // makes the first package's deps range run into the string table.
        binary[deps_count_pos..deps_count_pos + 2].copy_from_slice(&2u16.to_le_bytes());

        let (_dir, result) = open_bytes(&binary);
        assert!(
            result.is_err(),
            "open() should reject dependency spans that cross into the string table"
        );
    }

    #[test]
    fn truncated_entries_rejected_at_open() {
        // Build a valid binary, then set package_count to 100 while keeping
        // the file the same size (only enough room for 2 entries).
        // open() should now reject this with a structural validation error.
        let mut binary = sample_binary();
        let fake_count: u32 = 100;
        binary[8..12].copy_from_slice(&fake_count.to_le_bytes());

        let (_dir, result) = open_bytes(&binary);
        assert!(result.is_err(), "open() should reject inflated pkg_count");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("file too small") || err.contains("overlap"),
            "error should mention structural issue, got: {err}"
        );
    }

    /// M68: a binary lockfile whose string table is truncated such
    /// that a package's name/version range falls past EOF is now
    /// rejected at `open()` rather than silently surfacing `""`.
    /// Truncations that don't disturb the per-entry ranges (e.g.,
    /// trim trailing dep-table bytes) still produce a structural
    /// error via the layout consistency check.
    #[test]
    fn truncated_string_table_is_refused_at_open() {
        let binary = sample_binary();
        let truncated = &binary[..binary.len().saturating_sub(20).max(HEADER_SIZE)];

        let (_dir, result) = open_bytes(truncated);
        assert!(
            result.is_err(),
            "truncated string table must be refused, not surfaced as silently-empty fields"
        );
    }

    #[test]
    fn all_zeros_file() {
        let zeros = vec![0u8; 1024];
        let (_dir, result) = open_bytes(&zeros);
        // Magic is [0,0,0,0] != b"LPMB", should fail
        assert!(result.is_err());
    }

    #[test]
    fn random_bytes_file() {
        // Deterministic "random" bytes (not actually random, but non-LPMB)
        let mut bytes = vec![0u8; 1024];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((i * 137 + 43) % 256) as u8;
        }
        let (_dir, result) = open_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn version_zero_rejected() {
        let mut binary = sample_binary();
        // Set version to 0
        binary[4..8].copy_from_slice(&0u32.to_le_bytes());
        let (_dir, result) = open_bytes(&binary);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, LockfileError::UnsupportedVersion { found: 0, .. }),
            "expected UnsupportedVersion with found=0, got: {err:?}"
        );
    }

    #[test]
    fn version_255_rejected() {
        let mut binary = sample_binary();
        // Set version to 255
        binary[4..8].copy_from_slice(&255u32.to_le_bytes());
        let (_dir, result) = open_bytes(&binary);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, LockfileError::UnsupportedVersion { found: 255, .. }),
            "expected UnsupportedVersion with found=255, got: {err:?}"
        );
    }

    // ── Large lockfile tests ────────────────────────────────────────────────

    #[test]
    fn large_lockfile_1000_packages() {
        let mut lf = legacy_lockfile();
        for i in 0..1000 {
            lf.add_package(LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: format!("pkg-{i:04}"),
                version: format!("{}.0.0", i),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                integrity: Some(VALID_SHA512_SRI.to_string()),
                unpacked_size: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,

                dependencies: if i > 0 {
                    vec![format!("pkg-{:04}@{}.0.0", i - 1, i - 1)]
                } else {
                    vec![]
                },
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: None,
            });
        }
        let binary = to_binary(&lf).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        std::fs::write(&path, &binary).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        assert_eq!(reader.package_count(), 1000);

        // Binary search works
        let pkg = reader.find_package("pkg-0500").unwrap();
        assert_eq!(pkg.version(), "500.0.0");
        assert_eq!(pkg.dependencies(), vec!["pkg-0499@499.0.0"]);
    }

    #[test]
    fn package_with_many_deps() {
        let mut lf = legacy_lockfile();
        let deps: Vec<String> = (0..100).map(|i| format!("dep-{i:03}@1.0.0")).collect();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "big-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: deps,
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        for i in 0..100 {
            lf.add_package(LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: format!("dep-{i:03}"),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,

                dependencies: vec![],
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: None,
            });
        }

        let binary = to_binary(&lf).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        std::fs::write(&path, &binary).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let pkg = reader.find_package("big-pkg").unwrap();
        assert_eq!(pkg.dependencies().len(), 100);
    }

    #[test]
    fn large_lockfile_10000_packages() {
        let mut lf = legacy_lockfile();
        for i in 0..10000 {
            lf.add_package(LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: format!("pkg-{i:05}"),
                version: format!("{}.0.0", i),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                integrity: Some(VALID_SHA512_SRI.to_string()),
                unpacked_size: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,

                dependencies: if i > 0 {
                    vec![format!("pkg-{:05}@{}.0.0", i - 1, i - 1)]
                } else {
                    vec![]
                },
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: None,
            });
        }

        let binary = to_binary(&lf).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        std::fs::write(&path, &binary).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        assert_eq!(reader.package_count(), 10000);

        // Binary search works across all 10k
        let pkg = reader.find_package("pkg-05000").unwrap();
        assert_eq!(pkg.version(), "5000.0.0");
        assert_eq!(pkg.dependencies(), vec!["pkg-04999@4999.0.0"]);

        // First and last entries accessible
        let first = reader.find_package("pkg-00000").unwrap();
        assert_eq!(first.version(), "0.0.0");
        assert!(first.dependencies().is_empty());

        let last = reader.find_package("pkg-09999").unwrap();
        assert_eq!(last.version(), "9999.0.0");

        // Roundtrip preserves all packages
        let restored = reader.to_lockfile().unwrap();
        assert_eq!(restored.packages.len(), 10000);
    }

    #[test]
    fn roundtrip_toml_binary_toml() {
        let lf = sample_lockfile();
        let toml1 = lf.to_toml().unwrap();

        let binary = to_binary(&lf).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        std::fs::write(&path, &binary).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let restored = reader.to_lockfile().unwrap();
        let toml2 = restored.to_toml().unwrap();

        // TOML -> binary -> TOML produces identical output
        assert_eq!(toml1, toml2);
    }

    // ── read_str lower-bound validation ──────────────────────────────────

    /// M68: a corrupted name_off that points past the string table
    /// must be rejected at `open()` rather than silently surfacing
    /// `""` later. The TOML loader has always failed here; the
    /// binary loader now matches.
    #[test]
    fn open_rejects_name_offset_past_string_table() {
        let mut binary = sample_binary();
        let huge_off: u32 = u32::MAX;
        let name_len: u16 = 10;
        binary[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&huge_off.to_le_bytes());
        binary[HEADER_SIZE + 4..HEADER_SIZE + 6].copy_from_slice(&name_len.to_le_bytes());

        let (_dir, result) = open_bytes(&binary);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("name range") && (err.contains("overflows") || err.contains("past")),
            "error must label the bounds failure: {err}"
        );
    }

    // ── Structural validation (open-time header consistency) ──────────────

    #[test]
    fn open_rejects_string_table_off_past_eof() {
        let mut binary = sample_binary();
        // Set string_table_off to way past end of file
        let huge: u32 = (binary.len() as u32) + 10000;
        binary[12..16].copy_from_slice(&huge.to_le_bytes());
        let (_dir, result) = open_bytes(&binary);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("string table offset")
        );
    }

    #[test]
    fn open_rejects_entries_overlapping_string_table() {
        // Create a binary where pkg_count is high enough that entries
        // would extend past the declared string_table_off
        let mut binary = sample_binary();
        // Set pkg_count to 1000 but keep string_table_off where it is
        // (which is only enough for 2 entries)
        let big_count: u32 = 1000;
        binary[8..12].copy_from_slice(&big_count.to_le_bytes());
        let (_dir, result) = open_bytes(&binary);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("file too small") || err.contains("overlap"),
            "expected structural error, got: {err}"
        );
    }

    #[test]
    fn open_rejects_pkg_count_overflow() {
        let mut binary = sample_binary();
        // Set pkg_count to u32::MAX — even on 64-bit, the declared entries
        // will far exceed the file size
        binary[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let (_dir, result) = open_bytes(&binary);
        assert!(result.is_err(), "open() should reject u32::MAX pkg_count");
    }

    #[test]
    fn entry_at_rejects_index_beyond_pkg_count() {
        let binary = sample_binary();
        let (_dir, reader) = open_bytes(&binary);
        let reader = reader.unwrap().unwrap();
        assert_eq!(reader.package_count(), 2);
        // Index exactly at pkg_count should return None
        assert!(reader.entry_at(2).is_none());
        // Index beyond should also return None
        assert!(reader.entry_at(3).is_none());
        // Valid indices should work
        assert!(reader.entry_at(0).is_some());
        assert!(reader.entry_at(1).is_some());
    }

    // ── dependencies() checked arithmetic ────────────────────────────────

    #[test]
    fn deps_max_offset_no_panic() {
        // Set deps_off to u32::MAX and deps_count to 2.
        // On 32-bit, deps_off as usize + 1 would overflow without checked_add.
        let mut binary = sample_binary();
        let entry_base = HEADER_SIZE;
        let deps_off_pos = entry_base + 24;
        let deps_count_pos = entry_base + 28;

        binary[deps_off_pos..deps_off_pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        binary[deps_count_pos..deps_count_pos + 2].copy_from_slice(&2u16.to_le_bytes());

        let (_dir, reader) = open_bytes(&binary);
        let err = reader.unwrap_err();
        assert!(
            err.to_string()
                .contains("dependency range extends past dependency table")
                || err
                    .to_string()
                    .contains("dependency range overflows dependency table"),
            "expected dependency range validation error, got: {err}"
        );
    }

    // ── dep overflow check ───────────────────────────────────────────────

    #[test]
    fn dep_overflow_check_accounts_for_pending_deps() {
        // Verify the overflow check logic: new_total = current + about_to_add
        fn would_overflow(current: usize, to_add: usize) -> bool {
            current + to_add > u32::MAX as usize
        }
        assert!(would_overflow(u32::MAX as usize - 1, 2));
        assert!(would_overflow(u32::MAX as usize, 1));
        assert!(!would_overflow(100, 50));
        assert!(!would_overflow(0, u32::MAX as usize));
    }

    // ── String deduplication ──────────────────────────────────────────────

    #[test]
    fn string_dedup_reduces_size() {
        let source = "registry+https://registry.npmjs.org";
        let integrity = VALID_SHA512_SRI;
        let mut lf = legacy_lockfile();
        for i in 0..100 {
            lf.add_package(LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: format!("pkg-{i:03}"),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
                integrity: Some(integrity.to_string()),
                unpacked_size: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,

                dependencies: vec![],
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: None,
            });
        }

        let binary = to_binary(&lf).unwrap();

        // With dedup, the source and integrity strings should each appear
        // exactly once in the binary, not 100 times.
        let source_bytes = source.as_bytes();
        let source_occurrences = binary
            .windows(source_bytes.len())
            .filter(|w| *w == source_bytes)
            .count();
        assert_eq!(
            source_occurrences, 1,
            "deduplicated source string should appear exactly once in binary"
        );

        let integrity_bytes = integrity.as_bytes();
        let integrity_occurrences = binary
            .windows(integrity_bytes.len())
            .filter(|w| *w == integrity_bytes)
            .count();
        assert_eq!(
            integrity_occurrences, 1,
            "deduplicated integrity string should appear exactly once in binary"
        );

        // Version "1.0.0" is shared across all 100 packages — also deduped
        let version_bytes = b"1.0.0";
        let version_occurrences = binary
            .windows(version_bytes.len())
            .filter(|w| *w == version_bytes)
            .count();
        assert_eq!(
            version_occurrences, 1,
            "deduplicated version string should appear exactly once in binary"
        );

        // Verify roundtrip correctness
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        std::fs::write(&path, &binary).unwrap();
        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let restored = reader.to_lockfile().unwrap();
        assert_eq!(restored.packages.len(), 100);
        for pkg in &restored.packages {
            assert_eq!(pkg.source.as_deref(), Some(source));
            assert_eq!(pkg.integrity.as_deref(), Some(integrity));
        }
    }

    #[test]
    fn string_dedup_correctness() {
        // Verify that identical strings get the same (off, len)
        let mut st = StringTable::new();
        let (off1, len1) = st.insert("hello").unwrap();
        let (off2, _len2) = st.insert("world").unwrap();
        let (off3, len3) = st.insert("hello").unwrap();

        assert_eq!(
            (off1, len1),
            (off3, len3),
            "duplicate string should return same offset"
        );
        assert_ne!(
            off1, off2,
            "different strings should have different offsets"
        );
        assert_eq!(
            st.data.len(),
            10,
            "string table should only contain 'helloworld'"
        );
    }

    // ── Binary v3: sparse provenance with v2-sized package entries ─────────

    #[test]
    fn package_entry_size_remains_36_bytes_with_sparse_provenance() {
        assert_eq!(ENTRY_SIZE, 36, "package entry size must remain 36 bytes");
        assert_eq!(BINARY_VERSION, 3, "current BINARY_VERSION must be 3");
    }

    #[test]
    fn tarball_roundtrips_through_binary() {
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some(VALID_SHA512_SRI.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let entry = reader.find_package("lodash").unwrap();
        assert_eq!(
            entry.tarball(),
            Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
        );

        let restored = reader.to_lockfile().unwrap();
        assert_eq!(
            restored.packages[0].tarball.as_deref(),
            Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
        );
    }

    #[test]
    fn mixed_tarball_population_roundtrips() {
        // Rollout window — some entries have URL, some don't.
        // None must round-trip as None (null sentinel); Some must
        // preserve the exact bytes.
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        assert_eq!(reader.find_package("express").unwrap().tarball(), None);
        assert_eq!(
            reader.find_package("lodash").unwrap().tarball(),
            Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
        );
    }

    #[test]
    fn writer_rejects_empty_tarball() {
        // Third-pass audit: `(off=0, len=0)` is the null
        // sentinel. An empty-string tarball inserted into an empty
        // StringTable would yield exactly `(0, 0)` and become
        // indistinguishable from `None`. The writer must refuse.
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "empty-url-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: Some(String::new()),
        });

        let err = to_binary(&lf).expect_err("empty tarball must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("empty 'tarball'") && msg.contains("empty-url-pkg"),
            "error should name the field and package, got: {msg}"
        );
    }

    #[test]
    fn writer_rejects_empty_source_and_integrity_too() {
        // Same sentinel collision applies to `source` / `integrity`.
        // Historically the writer silently accepted them (falling to
        // the `(0, 0)` null sentinel, confusing readers into seeing
        // `None` where `Some("")` was intended). The writer rejects
        // empty strings across all three optional fields for consistency.
        let mut lf_source = legacy_lockfile();
        lf_source.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "pkg-with-empty-source".to_string(),
            version: "1.0.0".to_string(),
            source: Some(String::new()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        let err = to_binary(&lf_source).expect_err("empty source must be rejected");
        assert!(
            err.to_string().contains("source") && err.to_string().contains("empty"),
            "expected empty source rejection, got: {err}"
        );

        let mut lf_integ = legacy_lockfile();
        lf_integ.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "pkg-with-empty-integrity".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: Some(String::new()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        let err = to_binary(&lf_integ).expect_err("empty integrity must be rejected");
        assert!(
            err.to_string().contains("empty 'integrity'"),
            "expected empty integrity rejection, got: {err}"
        );
    }

    #[test]
    fn v2_reader_rejects_v1_binary_strict() {
        // A v2 reader decoding v1 entries (30 bytes each) as v2
        // entries (36 bytes each) would read package N's `name_off`
        // as package N-1's (nonexistent) tarball pair and produce
        // garbage. Strict `version != BINARY_VERSION` guard catches
        // this.
        //
        // We hand-roll a minimal "v1-looking" header — magic LPMB,
        // version=1, 0 packages, string_table_off=HEADER_SIZE. The
        // body doesn't need to be valid v1 past the header because
        // the version check fires first.
        let mut v1 = Vec::with_capacity(HEADER_SIZE);
        v1.extend_from_slice(MAGIC);
        v1.extend_from_slice(&1u32.to_le_bytes()); // version = 1 (old)
        v1.extend_from_slice(&0u32.to_le_bytes()); // 0 packages
        v1.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        assert_eq!(v1.len(), HEADER_SIZE);

        let (_dir, result) = open_bytes(&v1);
        match result {
            Err(LockfileError::UnsupportedVersion {
                found: 1,
                max_supported,
            }) => {
                assert_eq!(max_supported, BINARY_VERSION);
            }
            other => panic!("expected UnsupportedVersion {{ found: 1, .. }}, got: {other:?}"),
        }
    }

    #[test]
    fn v3_reader_rejects_future_version_4() {
        // Forward-incompat — a hypothetical v4 file must be rejected
        // by today's v3 reader (strict match, not `<= max`).
        let mut binary = sample_binary();
        binary[4..8].copy_from_slice(&4u32.to_le_bytes());
        let (_dir, result) = open_bytes(&binary);
        match result {
            Err(LockfileError::UnsupportedVersion { found: 4, .. }) => {}
            other => panic!("expected UnsupportedVersion with found=4, got: {other:?}"),
        }
    }

    #[test]
    fn open_rejects_corrupt_tarball_pair_zero_length_nonzero_offset() {
        // The range-overflow check passes `(off != 0, len == 0)`
        // trivially because `off + 0 > string_table_len` is false
        // for any in-bounds `off`. Combined with `tarball()`
        // treating "not both zero" as Some, this surfaces `Some("")`
        // on a corrupt pair. Explicit rejection closes the gap.
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "victim".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: Some("https://example.com/foo/-/foo-1.0.0.tgz".to_string()),
        });
        let mut binary = to_binary(&lf).unwrap();

        // Stomp: set tarball_off to some valid-looking non-zero
        // offset (5, well within the string table) but tarball_len
        // to 0. First round would have accepted; we now reject.
        let entry_base = HEADER_SIZE;
        binary[entry_base + 30..entry_base + 34].copy_from_slice(&5u32.to_le_bytes());
        binary[entry_base + 34..entry_base + 36].copy_from_slice(&0u16.to_le_bytes());

        let (_dir, result) = open_bytes(&binary);
        let err = result.expect_err("zero-length non-zero-offset must be rejected at open");
        let msg = err.to_string();
        assert!(
            msg.contains("non-zero offset with zero length") && msg.contains("null sentinel"),
            "expected orphan-offset rejection, got: {msg}"
        );
    }

    #[test]
    fn open_rejects_corrupt_tarball_pair() {
        // A corrupted tarball slot must force a TOML fallback at
        // `read_fast` time, NOT silently surface `Some("")` via the
        // `read_str` bounds-check degradation.
        //
        // Craft a valid binary then stomp the first entry's tarball
        // pair with an out-of-bounds offset that should trigger the
        // open-time validation.
        let lf = {
            let mut lf = legacy_lockfile();
            lf.add_package(LockedPackage {
                instance_id: None,
                dependency_targets: std::collections::BTreeMap::new(),
                peer_targets: std::collections::BTreeMap::new(),
                name: "victim".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                unpacked_size: None,
                manifest_fingerprint: None,
                registry_signatures: Vec::new(),
                registry_published_at: None,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                node_engine: None,
                optional: false,

                dependencies: vec![],
                alias_dependencies: vec![],
                peers: vec![],
                peer_edges: Vec::new(),
                tarball: Some("https://example.com/foo/-/foo-1.0.0.tgz".to_string()),
            });
            lf
        };
        let mut binary = to_binary(&lf).unwrap();

        // tarball_off at entry bytes [30..34], tarball_len at [34..36].
        // Set offset to u32::MAX with a non-zero length so the
        // validation branch (not the null sentinel) fires.
        let entry_base = HEADER_SIZE;
        binary[entry_base + 30..entry_base + 34].copy_from_slice(&u32::MAX.to_le_bytes());
        binary[entry_base + 34..entry_base + 36].copy_from_slice(&10u16.to_le_bytes());

        let (_dir, result) = open_bytes(&binary);
        let err = result.expect_err("corrupt tarball pair must be rejected at open");
        let msg = err.to_string();
        assert!(
            msg.contains("tarball range"),
            "expected tarball-range validation error, got: {msg}"
        );
    }

    #[test]
    fn null_tarball_sentinel_roundtrips() {
        // A package with `tarball: None` must round-trip as None,
        // not accidentally as `Some("")`. Exercises the (0, 0) =
        // None path of `tarball()` and confirms the writer didn't
        // emit spurious string-table bytes for the null case.
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "null-tarball-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });

        let binary = to_binary(&lf).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        std::fs::write(&path, &binary).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let entry = reader.find_package("null-tarball-pkg").unwrap();
        assert_eq!(entry.tarball(), None);
        assert_eq!(entry.source(), None);
        assert_eq!(entry.integrity(), None);
    }

    // ── Non-registry source binary round-trip ─────────────────────────────

    #[test]
    fn directory_source_round_trips_through_binary() {
        // `Source::Directory { path }` — the binary lockfile stores
        // the source string verbatim; readers parse it via
        // `Source::parse` downstream. No special wire format needed
        // for non-registry sources at the binary layer.
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "local-foo".to_string(),
            version: "0.1.0".to_string(),
            source: Some("directory+./packages/foo".to_string()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let entry = reader.find_package("local-foo").unwrap();
        assert_eq!(entry.source(), Some("directory+./packages/foo"));
        assert_eq!(entry.tarball(), None);

        let restored = reader.to_lockfile().unwrap();
        assert_eq!(restored, lf);
    }

    #[test]
    fn link_source_round_trips_through_binary() {
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "linked".to_string(),
            version: "0.1.0".to_string(),
            source: Some("link+../shared/linked".to_string()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let entry = reader.find_package("linked").unwrap();
        assert_eq!(entry.source(), Some("link+../shared/linked"));
        let restored = reader.to_lockfile().unwrap();
        assert_eq!(restored, lf);
    }

    #[test]
    fn tarball_local_source_round_trips_through_binary() {
        // `Source::Tarball { url: "file:..." }` — local-file tarball.
        // The wire format reuses `tarball+`; the URL prefix
        // discriminates downstream.
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "local-bundle".to_string(),
            version: "1.0.0".to_string(),
            source: Some("tarball+file:./vendor/local-bundle.tgz".to_string()),
            integrity: Some(VALID_SHA256_SRI.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let entry = reader.find_package("local-bundle").unwrap();
        assert_eq!(
            entry.source(),
            Some("tarball+file:./vendor/local-bundle.tgz"),
        );
        assert_eq!(entry.integrity(), Some(VALID_SHA256_SRI));
        // tarball field-hint is None for non-Registry sources.
        assert_eq!(entry.tarball(), None);
        let restored = reader.to_lockfile().unwrap();
        assert_eq!(restored, lf);
    }

    #[test]
    fn mixed_source_kinds_round_trip_through_binary() {
        // Cross-source identity at the binary layer: registry +
        // tarball-remote + tarball-local + directory + link all
        // co-exist with distinct source strings preserved.
        let mut lf = legacy_lockfile();
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some(VALID_SHA512_SRI.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
        });
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "remote-fork".to_string(),
            version: "1.0.0".to_string(),
            source: Some("tarball+https://e.com/remote.tgz".to_string()),
            integrity: Some(VALID_SHA512_SRI.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "local-tarball".to_string(),
            version: "1.0.0".to_string(),
            source: Some("tarball+file:./vendor/local.tgz".to_string()),
            integrity: Some(VALID_SHA256_SRI.to_string()),
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "local-dir".to_string(),
            version: "0.1.0".to_string(),
            source: Some("directory+./packages/local-dir".to_string()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });
        lf.add_package(LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "linked".to_string(),
            version: "0.1.0".to_string(),
            source: Some("link+../shared/linked".to_string()),
            integrity: None,
            unpacked_size: None,
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,

            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            peer_edges: Vec::new(),
            tarball: None,
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lpm.lockb");
        write_binary(&lf, &path).unwrap();

        let reader = BinaryLockfileReader::open(&path).unwrap().unwrap();
        let restored = reader.to_lockfile().unwrap();
        assert_eq!(restored.packages.len(), 5);
        // Every package's source string survives the round-trip
        // byte-equal — the binary lockfile doesn't pre-parse Source
        // variants, just stores the canonical wire string.
        for orig in &lf.packages {
            let rest = restored
                .packages
                .iter()
                .find(|p| p.name == orig.name)
                .expect("every package must round-trip");
            assert_eq!(rest.source, orig.source, "source drift for {}", orig.name);
            assert_eq!(rest.integrity, orig.integrity);
            assert_eq!(rest.tarball, orig.tarball);
        }
    }
}
