/// Per-package timing breakdown for the store-side stages of an install.
///
/// Emitted by [`PackageStore::store_package_from_file_timed`] so the
/// caller can split fetch-stage cost into its actual sub-stages
/// (extract vs security scan vs finalize) instead of a lumpy
/// `fetch_ms` number.
///
/// Duration fields are wall-clock values in whole milliseconds. A value of
/// zero is legitimate for stages that short-circuited (e.g. `extract_ms`
/// is zero when the package is already in the store — but the fast-path
/// caller at install-time never reaches this method). Count/byte fields are
/// zero when the store path cannot provide them without an extra traversal.
#[derive(Debug, Clone, Copy, Default)]
pub struct StageTimings {
    /// Time in `extract_tarball_from_file` (gzip decompress + tar walk
    /// + write-to-disk into the staging temp dir).
    pub extract_ms: u128,
    /// Time in `lpm_security::behavioral::analyze_package` plus the
    /// `.lpm-security.json` cache write.
    pub security_ms: u128,
    /// Time in integrity write + atomic rename + any remaining store
    /// bookkeeping before the package becomes visible.
    pub finalize_ms: u128,
    /// Time spent waiting for a v2 finalize permit before the actual
    /// finalization work starts. Zero unless the v2 finalize limiter is
    /// enabled by environment.
    pub finalize_permit_wait_ms: u128,
    /// Time spent computing and writing the v2 object tree integrity
    /// sidecars. Zero for store implementations that do not have an
    /// object-tree sidecar.
    pub finalize_tree_integrity_ms: u128,
    /// Time spent writing the package SRI sidecar.
    pub finalize_integrity_write_ms: u128,
    /// Time spent in the initial atomic rename attempt.
    pub finalize_rename_ms: u128,
    /// Time spent recovering from an atomic rename collision after a
    /// sibling task won the same object/package publication race.
    pub finalize_collision_recovery_ms: u128,
    /// Regular files observed while already walking the extracted object
    /// tree for integrity. Zero when the store path does not provide this
    /// count without an extra traversal.
    pub file_count: u64,
    /// Directories observed while already walking the extracted object tree
    /// for integrity. The object root itself is not counted.
    pub dir_count: u64,
    /// Symlinks observed while already walking the extracted object tree
    /// for integrity.
    pub symlink_count: u64,
    /// Sum of regular-file byte sizes observed during the object-tree
    /// integrity walk.
    pub unpacked_bytes: u64,
}
