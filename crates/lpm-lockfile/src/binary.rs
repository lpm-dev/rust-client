//! Binary lockfile format (`lpm.lockb`) for zero-parse-cost reads.
//!
//! Layout (v2, Phase 43):
//! ```text
//! [Header: 16 bytes]
//!   magic:              [u8; 4]  = b"LPMB"
//!   version:            u32 LE   = 2
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
//!   tarball_off:        u32 LE   — 0 means None (Phase 43, v2+)
//!   tarball_len:        u16 LE
//!
//! [DepsEntry × total_deps: 6 bytes each]
//!   str_off:            u32 LE   — offset into string table
//!   str_len:            u16 LE
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
//! On rejection, `read_fast` falls back to parsing the TOML
//! lockfile, and the next `write_all` rewrites `lpm.lockb` as the
//! current version — so the migration completes transparently on
//! any install that writes the lockfile (Phase 43 P43-2 adds a
//! dedicated writeback trigger so fast-path installs also complete
//! the migration).
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
/// Binary lockfile wire-format version. Bumped 1 → 2 in Phase 43
/// to append a `(tarball_off, tarball_len)` pair to every
/// `PackageEntry` (see layout docstring above). `pub` so
/// `read_fast` can distinguish older-version rejections (which
/// trigger best-effort cleanup of stale binaries) from
/// future-version rejections (which preserve the file for a
/// newer client's fast path).
pub const BINARY_VERSION: u32 = 2;
const HEADER_SIZE: usize = 16;
/// Per-package entry size. v1 was 30 bytes; v2 adds 6 bytes
/// (u32 tarball_off + u16 tarball_len).
const ENTRY_SIZE: usize = 36;
const DEP_ENTRY_SIZE: usize = 6;

/// Binary lockfile filename.
pub const BINARY_LOCKFILE_NAME: &str = "lpm.lockb";

// ── Writer ──────────────────────────────────────────────────────────────────

/// Binary format capability check — does this lockfile fit the wire format?
///
/// Phase 40 P2 — the binary format has no section for alias metadata
/// (neither v1 nor v2; Phase 43's v2 bump only added the tarball
/// slot). Projects with any npm-alias edges (root or transitive)
/// would be written with their alias info SILENTLY DROPPED, producing
/// a binary lockfile that disagrees with the TOML lockfile and a warm
/// install that re-creates `node_modules/<target>/` instead of
/// `node_modules/<local>/`. The install writer MUST check this
/// before calling `to_binary` and skip the binary write (falling
/// back to TOML-only) when aliases are present.
///
/// Returns `true` for alias-free lockfiles; `false` the moment any
/// alias field is populated.
pub fn binary_format_supports(lockfile: &Lockfile) -> bool {
    if !lockfile.root_aliases.is_empty() {
        return false;
    }
    lockfile
        .packages
        .iter()
        .all(|p| p.alias_dependencies.is_empty())
}

/// Serialize a `Lockfile` into the binary format.
///
/// Phase 40 P2 — returns `LockfileError::Serialize` when the
/// lockfile contains alias metadata. Callers should gate on
/// [`binary_format_supports`] and fall back to TOML-only when the
/// check fails.
pub fn to_binary(lockfile: &Lockfile) -> Result<Vec<u8>, LockfileError> {
    if !binary_format_supports(lockfile) {
        return Err(LockfileError::Serialize(
            "binary lockfile format cannot represent npm-alias metadata; \
             writer must fall back to TOML-only output"
                .to_string(),
        ));
    }

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
        /// Phase 43, v2+ — `(0, 0)` sentinel for None. Populated from
        /// `LockedPackage.tarball` via `insert_optional`, which
        /// rejects empty strings to keep the sentinel unambiguous.
        tarball: (u32, u16),
    }

    let mut pkg_infos = Vec::with_capacity(lockfile.packages.len());

    for pkg in &lockfile.packages {
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

    if lockfile.packages.len() > u32::MAX as usize {
        return Err(LockfileError::Serialize(format!(
            "too many packages for binary lockfile (max {})",
            u32::MAX
        )));
    }

    let pkg_count = lockfile.packages.len();
    let deps_section_offset = HEADER_SIZE + pkg_count * ENTRY_SIZE;
    let string_table_offset = deps_section_offset + dep_entries.len() * DEP_ENTRY_SIZE;

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
        // Phase 43, v2+ — tarball URL slot.
        buf.extend_from_slice(&info.tarball.0.to_le_bytes());
        buf.extend_from_slice(&info.tarball.1.to_le_bytes());
    }

    // Deps entries
    for (off, len) in &dep_entries {
        buf.extend_from_slice(&off.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
    }

    // String table
    buf.extend_from_slice(&strings.data);

    debug_assert_eq!(buf.len(), total_size);
    Ok(buf)
}

/// Write binary lockfile to disk atomically.
pub fn write_binary(lockfile: &Lockfile, path: &Path) -> Result<(), LockfileError> {
    let data = to_binary(lockfile)?;
    let tmp_path = path.with_extension("lockb.tmp");

    std::fs::write(&tmp_path, &data)
        .map_err(|e| LockfileError::Io(format!("failed to write {}: {e}", tmp_path.display())))?;

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(LockfileError::Io(format!(
            "failed to rename to {}: {e}",
            path.display()
        )));
    }

    Ok(())
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
        if !path.exists() {
            return Ok(None);
        }

        let file = std::fs::File::open(path)
            .map_err(|e| LockfileError::Io(format!("failed to open {}: {e}", path.display())))?;

        // SAFETY: we only read the file, no concurrent writes expected during install
        let mmap = unsafe {
            memmap2::Mmap::map(&file)
                .map_err(|e| LockfileError::Io(format!("failed to mmap {}: {e}", path.display())))?
        };

        // Validate header
        if mmap.len() < HEADER_SIZE {
            return Err(LockfileError::Deserialize(
                "binary lockfile too small".into(),
            ));
        }
        if &mmap[0..4] != MAGIC {
            return Err(LockfileError::Deserialize(
                "invalid binary lockfile magic".into(),
            ));
        }
        let version = u32::from_le_bytes(mmap[4..8].try_into().unwrap());
        // Strict version match — not `version > BINARY_VERSION`.
        // Per-entry layout differs across versions (v1 = 30B,
        // v2 = 36B), so decoding a v1 file as v2 (or vice versa)
        // produces garbage. `read_fast` catches this error and
        // falls through to TOML; the next `write_all` rewrites
        // `lpm.lockb` at the current version, completing the
        // migration transparently.
        if version != BINARY_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                found: version,
                max_supported: BINARY_VERSION,
            });
        }

        // Validate section layout consistency
        let pkg_count = u32::from_le_bytes(mmap[8..12].try_into().unwrap()) as usize;
        let string_table_off = u32::from_le_bytes(mmap[12..16].try_into().unwrap()) as usize;

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

        let deps_section_len = string_table_off - entries_end;
        if !deps_section_len.is_multiple_of(DEP_ENTRY_SIZE) {
            return Err(LockfileError::Deserialize(
                "dependency table is not aligned to entry size".into(),
            ));
        }

        let total_dep_entries = deps_section_len / DEP_ENTRY_SIZE;
        // Strings section runs from string_table_off to EOF.
        let string_table_len = mmap.len() - string_table_off;
        for idx in 0..pkg_count {
            let base = HEADER_SIZE + idx * ENTRY_SIZE;
            let deps_off =
                u32::from_le_bytes(mmap[base + 24..base + 28].try_into().unwrap()) as usize;
            let deps_count =
                u16::from_le_bytes(mmap[base + 28..base + 30].try_into().unwrap()) as usize;
            let deps_end = deps_off.checked_add(deps_count).ok_or_else(|| {
                LockfileError::Deserialize("dependency range overflows dependency table".into())
            })?;

            if deps_end > total_dep_entries {
                return Err(LockfileError::Deserialize(
                    "dependency range extends past dependency table".into(),
                ));
            }

            // Phase 43 — validate tarball pair eagerly so a corrupted
            // slot forces TOML fallback instead of silently surfacing
            // `Some("")` (which `read_str` returns on out-of-bounds
            // or zero-length reads).
            //
            // Invariant: the ONLY legitimate zero-length slot is the
            // null sentinel `(off=0, len=0)`. A non-null pair must
            // have `len > 0` AND fit inside the string table. Reject:
            //   - `len == 0 && off != 0` — orphan offset (2nd-round
            //     GPT audit catch: this was missed by the first
            //     follow-up because `len == 0` also makes
            //     `off + len > string_table_len` trivially false).
            //   - `off + len` overflows or exceeds the string table.
            let tarball_off =
                u32::from_le_bytes(mmap[base + 30..base + 34].try_into().unwrap()) as usize;
            let tarball_len =
                u16::from_le_bytes(mmap[base + 34..base + 36].try_into().unwrap()) as usize;
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
        }

        Ok(Some(Self { mmap }))
    }

    fn pkg_count(&self) -> u32 {
        u32::from_le_bytes(self.mmap[8..12].try_into().unwrap())
    }

    fn string_table_off(&self) -> usize {
        u32::from_le_bytes(self.mmap[12..16].try_into().unwrap()) as usize
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
            name_off: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            name_len: u16::from_le_bytes(b[4..6].try_into().unwrap()),
            version_off: u32::from_le_bytes(b[6..10].try_into().unwrap()),
            version_len: u16::from_le_bytes(b[10..12].try_into().unwrap()),
            source_off: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            source_len: u16::from_le_bytes(b[16..18].try_into().unwrap()),
            integrity_off: u32::from_le_bytes(b[18..22].try_into().unwrap()),
            integrity_len: u16::from_le_bytes(b[22..24].try_into().unwrap()),
            deps_off: u32::from_le_bytes(b[24..28].try_into().unwrap()),
            deps_count: u16::from_le_bytes(b[28..30].try_into().unwrap()),
            // Phase 43, v2+ — tarball slot at bytes [30..36]. Parses
            // cleanly on every v2 file; the null sentinel (0, 0)
            // decodes to `None` in `tarball()`.
            tarball_off: u32::from_le_bytes(b[30..34].try_into().unwrap()),
            tarball_len: u16::from_le_bytes(b[34..36].try_into().unwrap()),
        })
    }

    /// Binary search for a package by name. O(log n), zero-copy.
    ///
    /// **Phase 59.0 (post-review):** name-only lookup. Under
    /// cross-source collision (a registry package and a tarball-URL
    /// package with the same `(name, version)` in one lockfile),
    /// this returns whichever entry the binary search lands on —
    /// effectively arbitrary. New code MUST prefer
    /// [`Self::find_package_by_key`], which keys on the full
    /// `(name, version, source_id)` triple. This name-only method
    /// is retained for back-compat with pre-Phase-59 callers
    /// (Phase 40 P2 alias resolution etc.) where the lockfile is
    /// guaranteed registry-only and name uniquely identifies a
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

    /// **Phase 59.0 (post-review)** — source-aware lookup keyed by
    /// the full `(name, version, source_id)` triple. Mirrors
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

    /// Convert the binary lockfile back to a `Lockfile` struct.
    ///
    /// Note: the binary format does not store metadata fields (resolved_with),
    /// so the returned Lockfile uses the current defaults. The TOML lockfile is
    /// the source of truth for metadata; the binary format is a read-performance
    /// optimization only.
    pub fn to_lockfile(&self) -> Lockfile {
        let count = self.pkg_count() as usize;
        let mut packages = Vec::with_capacity(count);
        for i in 0..count {
            if let Some(entry) = self.entry_at(i) {
                packages.push(entry.to_locked_package());
            }
        }
        Lockfile {
            metadata: crate::LockfileMetadata {
                lockfile_version: crate::LOCKFILE_VERSION,
                resolved_with: Some("pubgrub".to_string()),
            },
            packages,
            // The binary format cannot represent alias metadata; any
            // project with aliases skips the binary write (see
            // `binary_format_supports`), so binary-backed reads always
            // correspond to an alias-free lockfile and this field is
            // always empty.
            root_aliases: std::collections::BTreeMap::new(),
        }
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
    /// Phase 43, v2+ — tarball URL slot. `(0, 0)` = None.
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

    /// Phase 43 — tarball URL as stored by the resolver. Used by
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
        let string_table_off = self.reader.string_table_off();
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
            if base_end > string_table_off || base_end > mmap_len {
                break;
            }
            let b = &self.reader.mmap[base..base + DEP_ENTRY_SIZE];
            let off = u32::from_le_bytes(b[0..4].try_into().unwrap());
            let len = u16::from_le_bytes(b[4..6].try_into().unwrap());
            deps.push(self.reader.read_str(off, len));
        }
        deps
    }

    /// **Phase 59.0 (post-review)** — three-tuple identity for this
    /// binary entry, mirroring [`LockedPackage::package_key`].
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
            name: self.name().to_string(),
            version: self.version().to_string(),
            source: self.source().map(|s| s.to_string()),
            integrity: self.integrity().map(|s| s.to_string()),
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
            // Phase 43, v2+ — read the tarball URL directly from the
            // mmap via the accessor; `None` when the slot is the
            // `(0, 0)` null sentinel.
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

    fn sample_lockfile() -> Lockfile {
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "@lpm.dev/neo.highlight".to_string(),
            version: "1.1.1".to_string(),
            source: Some("registry+https://lpm.dev".to_string()),
            integrity: Some("sha512-abc123".to_string()),
            dependencies: vec!["react@18.2.0".to_string()],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "18.2.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
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
        let restored = reader.to_lockfile();

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
        assert_eq!(highlight.integrity(), Some("sha512-abc123"));

        assert!(reader.find_package("nonexistent").is_none());
    }

    // ── Phase 59.0 (post-review): cross-source collision in binary lockfile ──
    // The binary lockfile fast path must offer the same source-aware
    // disambiguation guarantee as the TOML path. Without
    // `find_package_by_key`, a direct binary `find_package(name)`
    // call under a cross-source collision returns whichever entry
    // the binary search lands on — silently shadowing one side.

    fn cross_source_collision_lockfile() -> Lockfile {
        let mut lf = Lockfile::new();
        // Registry react@19.0.0 (the upstream)
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-registry".to_string()),
            dependencies: vec!["loose-envify@1.4.0".to_string()],
            alias_dependencies: vec![],
            tarball: None,
        });
        // Tarball-URL react@19.0.0 (a fork bundling the same name+version)
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "19.0.0".to_string(),
            source: Some("tarball+https://example.com/react-fork-19.0.0.tgz".to_string()),
            integrity: Some("sha512-fork".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
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
            Some("sha512-registry"),
            "registry key must return the registry entry, not the fork"
        );

        let tarball_entry = reader
            .find_package_by_key(&tarball_key)
            .expect("tarball side resolvable by key");
        assert_eq!(
            tarball_entry.integrity(),
            Some("sha512-fork"),
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
        // Drift-lock: any divergence between the binary fast path
        // and the TOML path would let `read_fast` return one answer
        // while `read_from_file` returns another.
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
    fn binary_empty_lockfile() {
        let lf = Lockfile::new();
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
    fn write_binary_rename_failure_cleans_temp_file() {
        let lf = sample_lockfile();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("lpm.lockb");

        std::fs::create_dir(&target).unwrap();

        let result = write_binary(&lf, &target);
        let tmp_path = target.with_extension("lockb.tmp");

        assert!(result.is_err(), "rename into a directory should fail");
        assert!(
            !tmp_path.exists(),
            "failed atomic write should clean its temp file: {}",
            tmp_path.display()
        );
    }

    // ── Corruption / bounds-check tests ─────────────────────────────────────

    #[test]
    fn read_str_oob_offset_returns_empty() {
        let mut binary = sample_binary();
        // Mutate the first package entry's name_off to a huge value
        // name_off is at HEADER_SIZE + 0 (first 4 bytes of first entry)
        let huge_off: u32 = 0xFFFF_FFFF;
        binary[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&huge_off.to_le_bytes());

        let (_dir, reader) = open_bytes(&binary);
        let reader = reader.unwrap().unwrap();
        // Should return "" instead of panicking
        let entry = reader.entry_at(0).unwrap();
        assert_eq!(entry.name(), "");
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

    #[test]
    fn truncated_string_table() {
        // Build valid binary then truncate file so strings are cut off
        let binary = sample_binary();
        let truncated = &binary[..binary.len().saturating_sub(20).max(HEADER_SIZE)];

        let (_dir, reader) = open_bytes(truncated);
        let reader = reader.unwrap().unwrap();
        // Reading entries with truncated strings should return "" not panic
        if let Some(entry) = reader.entry_at(0) {
            // These calls should not panic
            let _ = entry.name();
            let _ = entry.version();
            let _ = entry.source();
            let _ = entry.integrity();
            let _ = entry.dependencies();
        }
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
        let mut lf = Lockfile::new();
        for i in 0..1000 {
            lf.add_package(LockedPackage {
                name: format!("pkg-{i:04}"),
                version: format!("{}.0.0", i),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                integrity: Some("sha512-test".to_string()),
                dependencies: if i > 0 {
                    vec![format!("pkg-{:04}@{}.0.0", i - 1, i - 1)]
                } else {
                    vec![]
                },
                alias_dependencies: vec![],
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
        let mut lf = Lockfile::new();
        let deps: Vec<String> = (0..100).map(|i| format!("dep-{i:03}@1.0.0")).collect();
        lf.add_package(LockedPackage {
            name: "big-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: deps.clone(),
            alias_dependencies: vec![],
            tarball: None,
        });
        for i in 0..100 {
            lf.add_package(LockedPackage {
                name: format!("dep-{i:03}"),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                dependencies: vec![],
                alias_dependencies: vec![],
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
        let mut lf = Lockfile::new();
        for i in 0..10000 {
            lf.add_package(LockedPackage {
                name: format!("pkg-{i:05}"),
                version: format!("{}.0.0", i),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                integrity: Some("sha512-abcdef1234567890".to_string()),
                dependencies: if i > 0 {
                    vec![format!("pkg-{:05}@{}.0.0", i - 1, i - 1)]
                } else {
                    vec![]
                },
                alias_dependencies: vec![],
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
        let restored = reader.to_lockfile();
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
        let restored = reader.to_lockfile();
        let toml2 = restored.to_toml().unwrap();

        // TOML -> binary -> TOML produces identical output
        assert_eq!(toml1, toml2);
    }

    // ── Finding #1: read_str lower-bound validation ──────────────────────

    #[test]
    fn read_str_offset_into_header_returns_empty() {
        // Craft a binary lockfile, then corrupt a package entry's name_off
        // to point BEFORE the string table (into the header/entry region).
        let mut binary = sample_binary();
        // Set name_off of first entry to 0 but name_len to 4 — this would
        // read from string_table_off + 0 which is valid. Instead, we need
        // the absolute offset to land before string_table_off.
        // We'll set name_off to a value that, when added to string_table_off,
        // wraps on 32-bit or is otherwise invalid.
        //
        // Actually: the bug is that start < st_off wasn't checked. With the
        // old code, off=0 len=4 would read from string_table_off which is fine.
        // The real issue is when off as usize + st_off overflows.
        // On 64-bit, u32::MAX + st_off won't overflow usize, but it will be
        // past mmap.len(). The lower-bound check catches the case where
        // checked_add overflows (returns None -> "").
        //
        // Test: set name_off to u32::MAX, name_len to 10. On any platform,
        // st_off + u32::MAX will either overflow (caught by checked_add) or
        // exceed mmap.len().
        let huge_off: u32 = u32::MAX;
        let name_len: u16 = 10;
        binary[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&huge_off.to_le_bytes());
        binary[HEADER_SIZE + 4..HEADER_SIZE + 6].copy_from_slice(&name_len.to_le_bytes());

        let (_dir, reader) = open_bytes(&binary);
        let reader = reader.unwrap().unwrap();
        let entry = reader.entry_at(0).unwrap();
        assert_eq!(entry.name(), "");
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

    // ── Finding #2: dependencies() checked arithmetic ────────────────────

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

    // ── Finding #3: dep overflow check ───────────────────────────────────

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

    // ── Finding #7: string deduplication ─────────────────────────────────

    #[test]
    fn string_dedup_reduces_size() {
        let source = "registry+https://registry.npmjs.org";
        let integrity = "sha512-test";
        let mut lf = Lockfile::new();
        for i in 0..100 {
            lf.add_package(LockedPackage {
                name: format!("pkg-{i:03}"),
                version: "1.0.0".to_string(),
                source: Some(source.to_string()),
                integrity: Some(integrity.to_string()),
                dependencies: vec![],
                alias_dependencies: vec![],
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
        let restored = reader.to_lockfile();
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

    // ── Phase 43: binary v2 — tarball URL round-trip ───────────────────────

    #[test]
    fn phase43_entry_size_is_36_bytes() {
        // Wire-format invariant: v2 entries are 36 bytes (v1 was 30).
        // Guards against accidentally mis-sizing the writer/reader.
        assert_eq!(ENTRY_SIZE, 36, "v2 entry size must be 36 bytes");
        assert_eq!(BINARY_VERSION, 2, "Phase 43 targets BINARY_VERSION = 2");
    }

    #[test]
    fn phase43_tarball_roundtrips_through_binary() {
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-xyz".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
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

        let restored = reader.to_lockfile();
        assert_eq!(
            restored.packages[0].tarball.as_deref(),
            Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
        );
    }

    #[test]
    fn phase43_mixed_tarball_population_roundtrips() {
        // Rollout window — some entries have URL, some don't.
        // None must round-trip as None (null sentinel); Some must
        // preserve the exact bytes.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "express".to_string(),
            version: "4.22.1".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.add_package(LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
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
    fn phase43_writer_rejects_empty_tarball() {
        // M2 from 3rd-pass audit — `(off=0, len=0)` is the null
        // sentinel. An empty-string tarball inserted into an empty
        // StringTable would yield exactly `(0, 0)` and become
        // indistinguishable from `None`. The writer must refuse.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "empty-url-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
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
    fn phase43_writer_rejects_empty_source_and_integrity_too() {
        // Same sentinel collision applies to `source` / `integrity`.
        // Historically the writer silently accepted them (falling to
        // the `(0, 0)` null sentinel, confusing readers into seeing
        // `None` where `Some("")` was intended). Phase 43 tightens
        // this across all three optional fields for consistency.
        let mut lf_source = Lockfile::new();
        lf_source.add_package(LockedPackage {
            name: "pkg-with-empty-source".to_string(),
            version: "1.0.0".to_string(),
            source: Some(String::new()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        let err = to_binary(&lf_source).expect_err("empty source must be rejected");
        assert!(
            err.to_string().contains("empty 'source'"),
            "expected empty source rejection, got: {err}"
        );

        let mut lf_integ = Lockfile::new();
        lf_integ.add_package(LockedPackage {
            name: "pkg-with-empty-integrity".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: Some(String::new()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        let err = to_binary(&lf_integ).expect_err("empty integrity must be rejected");
        assert!(
            err.to_string().contains("empty 'integrity'"),
            "expected empty integrity rejection, got: {err}"
        );
    }

    #[test]
    fn phase43_v2_reader_rejects_v1_binary_strict() {
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
    fn phase43_v2_reader_rejects_future_version_3() {
        // Forward-incompat — a hypothetical v3 file must be rejected
        // by today's v2 reader (strict match, not `<= max`).
        let mut binary = sample_binary();
        binary[4..8].copy_from_slice(&3u32.to_le_bytes());
        let (_dir, result) = open_bytes(&binary);
        match result {
            Err(LockfileError::UnsupportedVersion { found: 3, .. }) => {}
            other => panic!("expected UnsupportedVersion with found=3, got: {other:?}"),
        }
    }

    #[test]
    fn phase43_open_rejects_corrupt_tarball_pair_zero_length_nonzero_offset() {
        // Second-round GPT audit (2026-04-18): the first
        // range-overflow check passed `(off != 0, len == 0)`
        // trivially because `off + 0 > string_table_len` is false
        // for any in-bounds `off`. Combined with `tarball()`
        // treating "not both zero" as Some, this surfaced `Some("")`
        // on a corrupt pair. Explicit rejection closes the gap.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "victim".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
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
    fn phase43_open_rejects_corrupt_tarball_pair() {
        // Follow-up to the 2026-04-18 GPT audit (finding #2): a
        // corrupted tarball slot must force a TOML fallback at
        // `read_fast` time, NOT silently surface `Some("")` via the
        // `read_str` bounds-check degradation.
        //
        // Craft a valid binary then stomp the first entry's tarball
        // pair with an out-of-bounds offset that should trigger the
        // open-time validation.
        let lf = {
            let mut lf = Lockfile::new();
            lf.add_package(LockedPackage {
                name: "victim".to_string(),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                dependencies: vec![],
                alias_dependencies: vec![],
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
    fn phase43_null_tarball_sentinel_roundtrips() {
        // A package with `tarball: None` must round-trip as None,
        // not accidentally as `Some("")`. Exercises the (0, 0) =
        // None path of `tarball()` and confirms the writer didn't
        // emit spurious string-table bytes for the null case.
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            name: "null-tarball-pkg".to_string(),
            version: "1.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
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
}
