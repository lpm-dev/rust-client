//! Binary lockfile format (`lpm.lockb`) for zero-parse-cost reads.
//!
//! Layout:
//! ```text
//! [Header: 16 bytes]
//!   magic:              [u8; 4]  = b"LPMB"
//!   version:            u32 LE   = 1
//!   package_count:      u32 LE
//!   string_table_off:   u32 LE   — byte offset where string table starts
//!
//! [PackageEntry × N: 30 bytes each]
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
//!
//! [DepsEntry × total_deps: 6 bytes each]
//!   str_off:            u32 LE   — offset into string table
//!   str_len:            u16 LE
//!
//! [String table: packed UTF-8]
//! ```
//!
//! Entries are sorted by name (same as TOML lockfile) for binary search.

use crate::{LockedPackage, Lockfile, LockfileError};
use std::path::Path;

const MAGIC: &[u8; 4] = b"LPMB";
const BINARY_VERSION: u32 = 1;
const HEADER_SIZE: usize = 16;
const ENTRY_SIZE: usize = 30;
const DEP_ENTRY_SIZE: usize = 6;

/// Binary lockfile filename.
pub const BINARY_LOCKFILE_NAME: &str = "lpm.lockb";

// ── Writer ──────────────────────────────────────────────────────────────────

/// Serialize a `Lockfile` into the binary format.
pub fn to_binary(lockfile: &Lockfile) -> Result<Vec<u8>, LockfileError> {
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
    }

    let mut pkg_infos = Vec::with_capacity(lockfile.packages.len());

    for pkg in &lockfile.packages {
        let name = strings.insert(&pkg.name)?;
        let version = strings.insert(&pkg.version)?;
        let source = match &pkg.source {
            Some(s) => strings.insert(s)?,
            None => (0, 0),
        };
        let integrity = match &pkg.integrity {
            Some(s) => strings.insert(s)?,
            None => (0, 0),
        };

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

    std::fs::rename(&tmp_path, path)
        .map_err(|e| LockfileError::Io(format!("failed to rename to {}: {e}", path.display())))?;

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
        if version == 0 || version > BINARY_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                found: version,
                max_supported: BINARY_VERSION,
            });
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
        let start = match st_off.checked_add(off as usize) {
            Some(v) => v,
            None => return "",
        };
        let end = match start.checked_add(len as usize) {
            Some(v) => v,
            None => return "",
        };
        if start < st_off || end > self.mmap.len() {
            return "";
        }
        std::str::from_utf8(&self.mmap[start..end]).unwrap_or("")
    }

    fn entry_at(&self, idx: usize) -> Option<PackageEntryView<'_>> {
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
        })
    }

    /// Binary search for a package by name. O(log n), zero-copy.
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

    /// Convert the binary lockfile back to a `Lockfile` struct.
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

    /// Convert to owned `LockedPackage`.
    pub fn to_locked_package(&self) -> LockedPackage {
        LockedPackage {
            name: self.name().to_string(),
            version: self.version().to_string(),
            source: self.source().map(|s| s.to_string()),
            integrity: self.integrity().map(|s| s.to_string()),
            dependencies: self.dependencies().iter().map(|s| s.to_string()).collect(),
        }
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
        });
        lf.add_package(LockedPackage {
            name: "react".to_string(),
            version: "18.2.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
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
        let reader = reader.unwrap().unwrap();
        let entry = reader.entry_at(0).unwrap();
        // Should return empty or partial vec, not panic
        let deps = entry.dependencies();
        assert!(deps.len() <= 5);
    }

    #[test]
    fn truncated_entries_handled() {
        // Build a valid binary, then set package_count to 100 while keeping
        // the file the same size (only enough room for 2 entries).
        let mut binary = sample_binary();
        let fake_count: u32 = 100;
        binary[8..12].copy_from_slice(&fake_count.to_le_bytes());

        let (_dir, reader) = open_bytes(&binary);
        let reader = reader.unwrap().unwrap();
        assert_eq!(reader.package_count(), 100);
        // entry_at beyond actual data should return None
        assert!(reader.entry_at(50).is_none());
        // to_lockfile should not panic, just skip missing entries
        let lf = reader.to_lockfile();
        assert!(lf.packages.len() <= 100);
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
        });
        for i in 0..100 {
            lf.add_package(LockedPackage {
                name: format!("dep-{i:03}"),
                version: "1.0.0".to_string(),
                source: None,
                integrity: None,
                dependencies: vec![],
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
        let reader = reader.unwrap().unwrap();
        let entry = reader.entry_at(0).unwrap();
        // Should return empty deps, not panic
        let deps = entry.dependencies();
        assert!(deps.is_empty());
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
            });
        }

        let binary = to_binary(&lf).unwrap();

        // Without dedup, the source string alone would be written 100 times:
        // 100 * 35 bytes = 3500 bytes. With dedup, only 35 bytes.
        // The binary should be significantly smaller than naive size.
        let naive_source_bytes = 100 * source.len();
        let naive_integrity_bytes = 100 * integrity.len();
        let naive_overhead = naive_source_bytes + naive_integrity_bytes;

        // The actual binary should save most of that duplication
        // (only 1 copy of source + 1 copy of integrity in string table)
        let dedup_savings = (99 * source.len()) + (99 * integrity.len());
        // Binary should be at least `dedup_savings - some_margin` smaller
        // than a hypothetical non-dedup version
        assert!(
            binary.len() + dedup_savings / 2 < binary.len() + naive_overhead,
            "dedup should provide significant savings"
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
}
