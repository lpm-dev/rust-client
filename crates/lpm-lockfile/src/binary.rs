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
//! [PackageEntry × N: 28 bytes each]
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
pub fn to_binary(lockfile: &Lockfile) -> Vec<u8> {
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
        let name = strings.insert(&pkg.name);
        let version = strings.insert(&pkg.version);
        let source = match &pkg.source {
            Some(s) => strings.insert(s),
            None => (0, 0),
        };
        let integrity = match &pkg.integrity {
            Some(s) => strings.insert(s),
            None => (0, 0),
        };

        let deps_off = dep_entries.len() as u32;
        let deps_count = pkg.dependencies.len() as u16;
        for dep in &pkg.dependencies {
            dep_entries.push(strings.insert(dep));
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
    buf
}

/// Write binary lockfile to disk atomically.
pub fn write_binary(lockfile: &Lockfile, path: &Path) -> Result<(), LockfileError> {
    let data = to_binary(lockfile);
    let tmp_path = path.with_extension("lockb.tmp");

    std::fs::write(&tmp_path, &data)
        .map_err(|e| LockfileError::Io(format!("failed to write {}: {e}", tmp_path.display())))?;

    std::fs::rename(&tmp_path, path)
        .map_err(|e| LockfileError::Io(format!("failed to rename to {}: {e}", path.display())))?;

    Ok(())
}

// ── Reader (mmap) ───────────────────────────────────────────────────────────

/// Memory-mapped binary lockfile reader. Zero-copy string access.
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
        if version > BINARY_VERSION {
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
        let start = self.string_table_off() + off as usize;
        let end = start + len as usize;
        std::str::from_utf8(&self.mmap[start..end]).unwrap_or("")
    }

    fn entry_at(&self, idx: usize) -> PackageEntryView<'_> {
        let base = HEADER_SIZE + idx * ENTRY_SIZE;
        let b = &self.mmap[base..base + ENTRY_SIZE];
        PackageEntryView {
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
        }
    }

    /// Binary search for a package by name. O(log n), zero-copy.
    pub fn find_package(&self, name: &str) -> Option<PackageEntryView<'_>> {
        let count = self.pkg_count() as usize;
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.entry_at(mid);
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
            let entry = self.entry_at(i);
            packages.push(entry.to_locked_package());
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
        (0..count).map(move |i| self.entry_at(i))
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
            Some(
                self.reader
                    .read_str(self.integrity_off, self.integrity_len),
            )
        }
    }

    pub fn dependencies(&self) -> Vec<&'a str> {
        let deps_section_start = HEADER_SIZE + self.reader.pkg_count() as usize * ENTRY_SIZE;
        let mut deps = Vec::with_capacity(self.deps_count as usize);
        for i in 0..self.deps_count as usize {
            let base = deps_section_start + (self.deps_off as usize + i) * DEP_ENTRY_SIZE;
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
}

impl StringTable {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Insert a string, returns (offset, length). No dedup for simplicity.
    fn insert(&mut self, s: &str) -> (u32, u16) {
        let off = self.data.len() as u32;
        let len = s.len() as u16;
        self.data.extend_from_slice(s.as_bytes());
        (off, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lockfile, LockedPackage};

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

    #[test]
    fn binary_roundtrip() {
        let lf = sample_lockfile();
        let binary = to_binary(&lf);

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
        assert_eq!(
            react.source(),
            Some("registry+https://registry.npmjs.org")
        );
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
        let binary = to_binary(&lf);
        let toml = lf.to_toml().unwrap();

        // Binary should be smaller than TOML
        assert!(
            binary.len() < toml.len(),
            "binary {} bytes >= toml {} bytes",
            binary.len(),
            toml.len()
        );
    }
}
