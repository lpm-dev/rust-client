/// Per-package timing breakdown for the store-side stages of an install.
///
/// Emitted by [`PackageStore::store_package_from_file_timed`] so the
/// caller can split fetch-stage cost into its actual sub-stages
/// (extract vs security scan vs finalize) instead of a lumpy
/// `fetch_ms` number.
///
/// All fields are wall-clock durations in whole milliseconds. A value of
/// zero is legitimate for stages that short-circuited (e.g. `extract_ms`
/// is zero when the package is already in the store — but the fast-path
/// caller at install-time never reaches this method).
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
}
