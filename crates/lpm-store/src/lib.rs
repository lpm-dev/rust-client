//! Content-addressable package store for LPM.
//!
//! Global store at `~/.lpm/store/` holds extracted packages keyed by
//! `name@version` hash. Projects link into this store via hardlinks or
//! copy-on-write (reflink on APFS/Btrfs).
//!
//! Layout:
//! ```text
//! ~/.lpm/store/
//!   v1/                          ← store version (for future migrations)
//!     react@19.2.4/              ← extracted package directory
//!       package.json
//!       index.js
//!       ...
//!     express@4.22.1/
//!       ...
//! ```
//!
//! Performance: package-level dedup (skip extraction on store hit), clonefile/reflink on macOS.
//! Maintenance: GC with age filtering, integrity verification (SRI hashes).

use lpm_common::integrity::{HashAlgorithm, Integrity};
use lpm_common::{LpmError, LpmRoot};
use sha2::{Digest, Sha512};
use std::path::{Path, PathBuf};

// Phase 66 Phase 4a: virtual-store v2 layout primitives. Currently
// dead code — Phase 4b wires writes behind `LPM_STORE_VERSION=v2`,
// Phase 4c teaches the read paths, Phase 4d flips the default. See
// `src/v2/mod.rs` for the on-disk shape and identity model.
pub mod v2;

/// Phase 66 store layout version selector.
///
/// Threaded through the install pipeline so a single env-var probe
/// at the top of `lpm install` decides whether the run materializes
/// to v1 (`<HOME>/.lpm/store/v1/...` + `<project>/.lpm/wrappers/...`)
/// or v2 (`<HOME>/.lpm/store/v2/{objects,links}/...` with project
/// `node_modules/<dep>` symlinks pointing into `links/<graph-key>/`).
///
/// **Default is v2 as of Phase 66 Phase 4d.** v1 stays available as
/// an explicit downgrade via `LPM_STORE_VERSION=v1` for users who
/// hit a v2 regression and need to roll back without redownloading
/// lpm-rs. The pre-Phase-4d default was v1; Phase 4d wires the v1 →
/// v2 migration sequence into the install pipeline so the flip is
/// silent for upgrade-in-place users.
///
/// Read once per install via [`StoreVersion::from_env`] so a single
/// invocation is internally consistent — flipping the env mid-install
/// would otherwise produce a half-v1/half-v2 layout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum StoreVersion {
    /// Pre-Phase-4d default — wrappers under `<project>/.lpm/wrappers/`,
    /// canonical bytes at `<HOME>/.lpm/store/v1/<pkg>/<version>/`.
    /// Now selected only via explicit `LPM_STORE_VERSION=v1`
    /// (downgrade-rollback path).
    V1,
    /// Virtual-store layout — canonical bytes at
    /// `<HOME>/.lpm/store/v2/objects/<sri>/`, per-context wrappers at
    /// `<HOME>/.lpm/store/v2/links/<graph-key>/`, project
    /// `node_modules/<dep>` is a symlink into the link entry. **Default
    /// from Phase 4d onward.**
    #[default]
    V2,
}

impl StoreVersion {
    /// Env var name. Defined as a constant so callers that want to
    /// log "the user set X" can reference it without re-string-typing.
    pub const ENV_VAR: &'static str = "LPM_STORE_VERSION";

    /// Read the active store version from `LPM_STORE_VERSION`. Returns
    /// `V2` (the Phase-4d default) when the var is unset; recognized
    /// values otherwise.
    ///
    /// Recognized values:
    /// - Unset, empty, or `v2`/`2` → `V2` (default).
    /// - `v1`/`1` → `V1` (explicit downgrade-rollback for users
    ///   hitting a v2 regression).
    /// - Anything else → `V2` + a warning trace, so a typo doesn't
    ///   silently activate v1.
    ///
    /// Trimmed and lowercased for ergonomics.
    pub fn from_env() -> Self {
        Self::parse(std::env::var(Self::ENV_VAR).ok().as_deref())
    }

    /// Pure parser for the env-var value. Extracted from
    /// [`Self::from_env`] so unit tests can exercise the recognized /
    /// rejected / fallback branches without manipulating process
    /// environment (which would race other parallel tests).
    pub fn parse(raw: Option<&str>) -> Self {
        let Some(raw) = raw else {
            return Self::V2;
        };
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "" | "v2" | "2" => Self::V2,
            "v1" | "1" => Self::V1,
            other => {
                tracing::warn!(
                    "{}={other:?} not recognized; falling back to v2 (valid: v1, v2)",
                    Self::ENV_VAR
                );
                Self::V2
            }
        }
    }

    /// `true` iff this is [`StoreVersion::V2`].
    pub fn is_v2(self) -> bool {
        matches!(self, Self::V2)
    }
}

impl std::fmt::Display for StoreVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => f.write_str("v1"),
            Self::V2 => f.write_str("v2"),
        }
    }
}

/// Store version for the directory layout.
const STORE_VERSION: &str = "v1";

/// Per-package timing breakdown for the store-side stages of an install.
///
/// Emitted by [`PackageStore::store_package_from_file_timed`] so the caller
/// can split fetch-stage cost into its actual sub-stages (extract vs
/// security scan vs finalize). Used by Phase 38 P0 instrumentation to
/// replace the lumpy `fetch_ms` number with a principled breakdown.
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

/// The global content-addressable package store.
#[derive(Clone)]
pub struct PackageStore {
    /// Root directory of the store (e.g., ~/.lpm/store).
    root: PathBuf,
    /// `~/.lpm/store/v1/` — precomputed to avoid one PathBuf
    /// allocation per `package_dir` call on hot install paths.
    v1_root: PathBuf,
}

impl PackageStore {
    /// Create a store at the default location (`~/.lpm/store`).
    ///
    /// Thin convenience wrapper around [`PackageStore::from_root`] that
    /// resolves the LPM home through [`LpmRoot::from_env`]. Prefer
    /// [`PackageStore::from_root`] when the caller already has an
    /// `LpmRoot` in scope — the store then shares the same home-resolution
    /// decision as every other path in the command.
    pub fn default_location() -> Result<Self, LpmError> {
        Ok(Self::from_root(&LpmRoot::from_env()?))
    }

    /// Create a store rooted at the given [`LpmRoot`]'s `store/` directory.
    pub fn from_root(root: &LpmRoot) -> Self {
        let store_root = root.store_root();
        let v1_root = store_root.join(STORE_VERSION);
        PackageStore {
            root: store_root,
            v1_root,
        }
    }

    /// Create a store at a specific path (for testing).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let v1_root = root.join(STORE_VERSION);
        PackageStore { root, v1_root }
    }

    /// Derive an [`lpm_common::LpmRoot`] from this store's root.
    /// `PackageStore::root` is `<lpm_root>/store/`, so the LpmRoot is
    /// the parent. Used by callers that need to consult the v2
    /// virtual store (constructed via [`crate::v2::Store::from_lpm_root`])
    /// without threading an additional `LpmRoot` parameter through
    /// every API.
    pub fn lpm_root(&self) -> Result<lpm_common::LpmRoot, LpmError> {
        let parent = self.root.parent().ok_or_else(|| {
            LpmError::Store(format!(
                "package store root {:?} has no parent — cannot derive LpmRoot",
                self.root
            ))
        })?;
        Ok(lpm_common::LpmRoot::from_dir(parent))
    }

    /// Get the store directory for a package version.
    /// e.g., `~/.lpm/store/v1/react@19.2.4/`
    pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
        use std::borrow::Cow;
        // Avoid heap alloc for the common case of unscoped packages.
        let safe_name: Cow<'_, str> = if name.contains(['/', '\\']) {
            Cow::Owned(name.replace(['/', '\\'], "+"))
        } else {
            Cow::Borrowed(name)
        };
        self.v1_root.join(format!("{safe_name}@{version}"))
    }

    /// **Phase 59.0 day-4 (F4)** — content-addressable store path
    /// for a non-Registry tarball, keyed by SRI integrity hash.
    ///
    /// Layout: `~/.lpm/store/v1/tarball/{algo}-{hex}/`
    ///
    /// - `{algo}` is `sha256` or `sha512` (matching the SRI input).
    /// - `{hex}` is the lowercase hex of the raw hash bytes (64
    ///   chars for SHA-256, 128 for SHA-512). Hex (vs base64) keeps
    ///   the directory name filesystem-safe on every platform —
    ///   no `/`, `+`, or `=` characters.
    ///
    /// This is the `Source::Tarball` arm of the store layout — the
    /// Registry arm continues to use [`Self::package_dir`] keyed by
    /// `(name, version)`. Both arms share the `STORE_VERSION` root
    /// so a future schema bump moves them together.
    ///
    /// Day-4 is additive (no caller wired); day-5 routes
    /// `Source::Tarball` resolutions through this path.
    ///
    /// Returns [`LpmError::InvalidIntegrity`] if `integrity_sri`
    /// can't be parsed as a canonical SRI string.
    pub fn tarball_store_path(&self, integrity_sri: &str) -> Result<PathBuf, LpmError> {
        let int = Integrity::parse(integrity_sri)?;
        let algo = match int.algorithm {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        };
        let hex: String = int.hash.iter().map(|b| format!("{b:02x}")).collect();
        Ok(self
            .root
            .join(STORE_VERSION)
            .join("tarball")
            .join(format!("{algo}-{hex}")))
    }

    /// Phase 59.0 day-4 — whether a `Source::Tarball` payload is
    /// already extracted at its CAS path. Mirrors
    /// [`Self::has_package`] for the Registry arm.
    pub fn has_tarball(&self, integrity_sri: &str) -> bool {
        match self.tarball_store_path(integrity_sri) {
            Ok(dir) => is_complete_package_dir(&dir),
            Err(_) => false,
        }
    }

    /// **Phase 59.1 day-1 (F6)** — content-addressable store path
    /// for a local-file tarball (`file:./foo.tgz`), keyed by the
    /// SHA-256 of the tarball bytes.
    ///
    /// Layout: `~/.lpm/store/v1/tarball-local/sha256-{hex}/`
    ///
    /// Distinct from [`Self::tarball_store_path`] (the remote-tarball
    /// arm under `v1/tarball/`) because identity differs:
    /// - **Remote tarball** (`Source::Tarball { url: "https://..." }`):
    ///   identity is the SRI declared in the manifest or computed on
    ///   first fetch; the store key is `{algo}-{hex}` so a sha256-
    ///   declared dep and a sha512-declared dep on the same content
    ///   land in distinct slots.
    /// - **Local tarball** (`Source::Tarball { url: "file:..." }`):
    ///   identity is the **content** (URL has no integrity guarantees
    ///   on the local filesystem). The hash is always SHA-256 of the
    ///   tarball bytes; the store key is `sha256-{hex}` of those
    ///   bytes. Two different `file:` paths to the same content
    ///   dedupe to one CAS slot.
    ///
    /// `content_sha256_hex` MUST be exactly 64 lowercase hex
    /// characters (the SHA-256 digest of the tarball bytes). Returns
    /// [`LpmError::InvalidIntegrity`] otherwise — same error shape as
    /// [`Self::tarball_store_path`] so callers can route both arms
    /// through one error path.
    ///
    /// Both subtrees share `STORE_VERSION` so a future schema bump
    /// moves them together (matching 59.0 day-5a's locked decision).
    pub fn tarball_local_store_path(&self, content_sha256_hex: &str) -> Result<PathBuf, LpmError> {
        validate_sha256_hex(content_sha256_hex)?;
        Ok(self
            .root
            .join(STORE_VERSION)
            .join("tarball-local")
            .join(format!("sha256-{content_sha256_hex}")))
    }

    /// **Phase 59.1 day-1 (F6)** — whether a local-file tarball
    /// payload is already extracted at its CAS path. Mirrors
    /// [`Self::has_tarball`] for the remote-tarball arm.
    pub fn has_local_tarball(&self, content_sha256_hex: &str) -> bool {
        match self.tarball_local_store_path(content_sha256_hex) {
            Ok(dir) => is_complete_package_dir(&dir),
            Err(_) => false,
        }
    }

    /// Check if a package version is already in the store.
    pub fn has_package(&self, name: &str, version: &str) -> bool {
        let dir = self.package_dir(name, version);
        is_complete_package_dir(&dir)
    }

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

    /// **Phase 59.0 day-5 (F4 install-side wiring)** — extract a
    /// `Source::Tarball` payload into the content-addressable
    /// tarball CAS path keyed by SRI integrity.
    ///
    /// Mirrors [`Self::store_package`] semantically but uses
    /// [`Self::tarball_store_path`] for the destination directory
    /// instead of `(name, version)`. All TOCTOU + integrity +
    /// behavioral-analysis machinery is shared with `store_package`
    /// via the private [`Self::store_at_dir`] helper.
    ///
    /// `integrity_sri` MUST be the SRI of `tarball_data` — usually
    /// this is the value returned by
    /// [`lpm_registry::RegistryClient::download_tarball_with_integrity`].
    /// Mismatching the two would route a tarball into the wrong CAS
    /// slot. The caller is responsible for keeping them aligned;
    /// this method does not re-verify (re-hashing on the install
    /// hot path is wasteful given the download already did it).
    ///
    /// Returns [`LpmError::InvalidIntegrity`] if `integrity_sri`
    /// can't be parsed.
    pub fn store_tarball_at_cas_path(
        &self,
        integrity_sri: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        let dir = self.tarball_store_path(integrity_sri)?;
        // The label appears in tracing/error messages — keep it
        // short. The full SRI is long (sha512 + 88 base64 chars);
        // truncate at the first '-' + 16 chars for readability.
        let label = format!(
            "tarball:{}",
            integrity_sri.chars().take(24).collect::<String>()
        );
        self.store_at_dir(dir, &label, tarball_data)
    }

    /// **Phase 59.1 day-1 (F6 install-side wiring)** — extract a
    /// local-file tarball into the content-addressable
    /// `tarball-local` CAS path keyed by content SHA-256.
    ///
    /// Mirrors [`Self::store_tarball_at_cas_path`] but routes through
    /// [`Self::tarball_local_store_path`] for the destination
    /// directory. All TOCTOU + integrity + behavioral-analysis
    /// machinery is shared with the registry/remote-tarball arms via
    /// the private [`Self::store_at_dir`] helper — `.integrity`
    /// (SRI of the bytes) and `.lpm-security.json` are written in
    /// the same atomic-rename window.
    ///
    /// `content_sha256_hex` MUST be the lowercase-hex SHA-256 of
    /// `tarball_data` — the caller is responsible for keeping them
    /// aligned. This method does not re-hash on the install hot path
    /// (matching the contract on [`Self::store_tarball_at_cas_path`]).
    ///
    /// Returns [`LpmError::InvalidIntegrity`] if `content_sha256_hex`
    /// fails the validation in [`Self::tarball_local_store_path`].
    pub fn store_local_tarball_at_cas_path(
        &self,
        content_sha256_hex: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        let dir = self.tarball_local_store_path(content_sha256_hex)?;
        // Truncate to the first 16 hex chars in tracing labels —
        // matching the remote-tarball arm's labelling style. Adds a
        // `local:` prefix so log/error messages disambiguate at a
        // glance from the integrity-keyed remote arm.
        let label = format!(
            "local-tarball:sha256-{}",
            &content_sha256_hex[..16.min(content_sha256_hex.len())]
        );
        self.store_at_dir(dir, &label, tarball_data)
    }

    /// Shared inner extraction logic used by [`Self::store_package`]
    /// and [`Self::store_tarball_at_cas_path`].
    ///
    /// `dir` is the destination directory (different per-source-kind).
    /// `label` is a human-readable identifier for tracing/error
    /// messages; carries `name@version` for Registry sources or a
    /// truncated SRI for Tarball sources.
    fn store_at_dir(
        &self,
        dir: PathBuf,
        label: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        // Fast path: already stored
        if dir.exists() {
            if is_complete_package_dir(&dir) {
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

        // Write SRI integrity hash of the original tarball for later verification.
        // This allows `store verify --deep` to detect post-extraction tampering.
        let sri = compute_sri_hash(tarball_data);
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), &sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!("failed to write .integrity: {e}")));
        }

        // Run behavioral security analysis and write .lpm-security.json.
        // Done BEFORE the atomic rename so the analysis result is included
        // atomically — when the package dir becomes visible, the security
        // cache is already present. Analysis failure is non-fatal (warn only).
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

    /// Phase 38 P1 streaming path: hash + decompress + extract + scan +
    /// rename, all in one pass, no temp file.
    ///
    /// The caller pipes a tarball byte stream into `reader` (typically a
    /// [`tokio::io::SyncIoBridge`] over a [`tokio_util::io::StreamReader`]
    /// built from `reqwest::Response::bytes_stream()`). This method runs
    /// synchronously inside a `spawn_blocking` task because `flate2` +
    /// `tar::Archive` are sync and CPU-bound.
    ///
    /// ## Pipeline
    /// ```text
    /// reader  ──►  SizeLimitedReader  ──►  HashingReader  ──►  GzDecoder
    ///           (500 MB ceiling)        (SHA-512 tee)        (flate2/zlib-rs)
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

        tracing::debug!("streaming {name}@{version} into store (P1)");

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
        // "reopen + extract" + "walk extracted tree". With P1+P2 all three
        // collapse into a single filesystem pass — the extractor hands each
        // scannable entry's bytes to the analyzer while still holding them
        // in the write buffer.
        let extract_start = std::time::Instant::now();
        let size_limited = SizeLimitedReader::new(reader, max_compressed_size);
        let mut hashing_reader = HashingReader::new(size_limited);

        // Phase 38 P2: fused behavioral scan. `PackageAnalyzer::should_scan`
        // is the buffer predicate — returns true for JS/TS/JSX/TSX sources
        // outside `node_modules`/`__tests__`/`test`/hidden paths, which is
        // exactly the set the pre-P2 `collect_source_files_recursive` filter
        // produced. The inspector closure feeds those buffered bytes into
        // the analyzer. Non-source files stream through `entry.unpack()`
        // unchanged — zero extra memory for the long tail of package
        // contents (images, fonts, .map files, etc).
        let analyzer = std::cell::RefCell::new(lpm_security::behavioral::PackageAnalyzer::new());

        // `&mut HashingReader` satisfies `impl Read` via the blanket impl
        // `impl<R: Read> Read for &mut R`, so we retain ownership and can
        // call `finalize` after extraction completes. Extractor errors
        // (including `SizeLimitedReader` tripping its cap via `Read` returning
        // an error) propagate through here unchanged.
        let extract_result = lpm_extractor::extract_tarball_from_reader_with_inspector(
            &mut hashing_reader,
            &tmp_dir,
            lpm_security::behavioral::PackageAnalyzer::should_scan,
            |entry| {
                if let Some(bytes) = entry.bytes {
                    analyzer.borrow_mut().feed(entry.relative_path, bytes);
                }
            },
        );

        if let Err(error) = extract_result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            let _ = hashing_reader.finalize(); // discard partial hash
            return Err(error);
        }

        // Critical for SRI correctness: drain any trailing bytes through the
        // hasher. `tar::Archive` stops pulling from its inner `GzDecoder` as
        // soon as it hits the two-zero-block end-of-archive marker, and
        // `GzDecoder` may in turn have buffered but not fully consumed the
        // underlying stream. Any gzip trailer bytes / tar padding / block
        // alignment past the archive end are part of the compressed `.tgz`
        // the registry hashed — miss them and the computed SRI diverges from
        // the registry's, causing the per-package integrity check to spuriously
        // fail (reproduced on ~20% of 51-package installs before this drain
        // was added). `io::sink()` discards the bytes; the hasher update
        // inside `HashingReader::read` still fires on every byte.
        if let Err(e) = std::io::copy(&mut hashing_reader, &mut std::io::sink()) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            let _ = hashing_reader.finalize();
            return Err(LpmError::Io(e));
        }

        let (computed_sri, _compressed_size) = hashing_reader.finalize();
        timings.extract_ms = extract_start.elapsed().as_millis();

        // Compare against expected integrity before the scan / rename.
        // Scope: sha512-only (see doc comment). Non-sha512 expected values
        // fall through; the caller chose the wrong path.
        if let Some(expected) = expected_integrity {
            if expected.starts_with("sha512-") && expected != computed_sri {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(LpmError::Registry(format!(
                    "integrity mismatch for {name}@{version}: expected {expected}, got {computed_sri}"
                )));
            }
            // Non-sha512 expected → log + trust computed (same fallback as
            // download_tarball_to_file's path when verify_integrity_file
            // succeeds with a different algo).
            if !expected.starts_with("sha512-") {
                tracing::warn!(
                    "non-sha512 expected integrity for {name}@{version} — P1 streaming path trusts computed sha512"
                );
            }
        }

        // Phase 38 P2: security analysis was fused into the tar walk above.
        // What remains is finalize — read `package.json` from the staging
        // dir (one file open, always present in npm tarballs), run the
        // manifest-level tag analysis, merge dedup'd URL domains, compute
        // the package-level `trivial` tag, and serialize to
        // `.lpm-security.json`. Per-source-file bytes are not re-read; the
        // fused scan already consumed them.
        let security_start = std::time::Instant::now();
        let analysis = analyzer.into_inner().finalize(&tmp_dir);
        if let Err(e) = lpm_security::behavioral::write_cached_analysis(&tmp_dir, &analysis) {
            tracing::warn!("failed to write .lpm-security.json for {name}@{version}: {e}");
        }
        timings.security_ms = security_start.elapsed().as_millis();

        // Finalize: write integrity, atomic rename.
        let finalize_start = std::time::Instant::now();
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), &computed_sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!("failed to write .integrity: {e}")));
        }
        let rename_result = std::fs::rename(&tmp_dir, &dir);
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
    /// `extract_ms` covers `extract_tarball_from_file`; `security_ms` covers
    /// `analyze_package` + `.lpm-security.json` write; `finalize_ms` covers
    /// the `.integrity` file write plus the atomic rename. The sum of the
    /// three is the wall-clock of the miss path excluding the initial
    /// `dir.exists()` stat.
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

        // Write pre-computed SRI hash (no second pass needed). This runs
        // before the security scan to preserve the pre-Phase-38 execution
        // order — Phase 38 P0 is instrumentation-only; behavior stays put.
        // Counted under `finalize_ms` because it's cheap housekeeping, not
        // a sub-stage we expect to optimize separately.
        let finalize_start = std::time::Instant::now();
        if let Err(e) = std::fs::write(tmp_dir.join(".integrity"), sri) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(LpmError::Store(format!("failed to write .integrity: {e}")));
        }
        let integrity_write_ms = finalize_start.elapsed().as_millis();

        // Security analysis runs on the extracted tree before the atomic
        // rename so the `.lpm-security.json` cache is visible atomically
        // alongside the package. Measured separately from finalize so we
        // can see the second-filesystem-pass cost that Phase 38 P2 targets.
        let security_start = std::time::Instant::now();
        let analysis = lpm_security::behavioral::analyze_package(&tmp_dir);
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

        // Finalize: atomic rename into the visible path.
        let rename_start = std::time::Instant::now();
        let rename_result = std::fs::rename(&tmp_dir, &dir);
        timings.finalize_ms = integrity_write_ms + rename_start.elapsed().as_millis();

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

    /// List all packages in the store.
    pub fn list_packages(&self) -> Result<Vec<(String, String)>, LpmError> {
        let store_dir = self.root.join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(Vec::new());
        }

        let mut packages = Vec::new();
        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let dir_name = entry.file_name().to_string_lossy().to_string();
            if let Some(package) = complete_package_from_dir(&entry.path(), &dir_name) {
                packages.push(package);
            }
        }

        packages.sort();
        Ok(packages)
    }

    /// Get the store root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Garbage collection: remove packages from the store that are not referenced
    /// by any project's lockfile.
    ///
    /// `referenced` is a set of "name@version" strings that should be kept.
    /// Everything else in the store is removed.
    ///
    /// If `max_age` is provided, only unreferenced packages whose directory mtime
    /// is older than `now - max_age` are removed. This allows keeping recently-used
    /// packages even if they're not in the current lockfile.
    pub fn gc(
        &self,
        referenced: &std::collections::HashSet<String>,
        max_age: Option<&std::time::Duration>,
    ) -> Result<GcResult, LpmError> {
        let store_dir = self.root.join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(GcResult {
                removed: 0,
                kept: 0,
                freed_bytes: 0,
            });
        }

        let now = std::time::SystemTime::now();
        let mut removed = 0;
        let mut kept = 0;
        let mut freed_bytes: u64 = 0;

        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let dir_name = entry.file_name().to_string_lossy().to_string();

            if let Some((pkg_name, version)) = complete_package_from_dir(&entry.path(), &dir_name) {
                let key = format!("{pkg_name}@{version}");

                if referenced.contains(&key) {
                    kept += 1;
                    continue;
                }

                // Check age filter: skip if the package was modified recently
                if let Some(age_threshold) = max_age
                    && let Ok(meta) = entry.metadata()
                    && let Ok(mtime) = meta.modified()
                    && let Ok(elapsed) = now.duration_since(mtime)
                    && elapsed < *age_threshold
                {
                    kept += 1;
                    continue;
                }

                // Calculate size before removing
                freed_bytes += dir_size(&entry.path());
                std::fs::remove_dir_all(entry.path())?;
                removed += 1;
                continue;
            }

            if is_junk_store_dir(&entry.path(), &dir_name) {
                std::fs::remove_dir_all(entry.path())?;
            }
        }

        Ok(GcResult {
            removed,
            kept,
            freed_bytes,
        })
    }

    /// Preview what GC would remove, without actually deleting anything.
    ///
    /// Returns a list of package names and their sizes that would be removed,
    /// plus the count of packages that would be kept.
    pub fn gc_preview(
        &self,
        referenced: &std::collections::HashSet<String>,
        max_age: Option<&std::time::Duration>,
    ) -> Result<GcPreview, LpmError> {
        let store_dir = self.root.join(STORE_VERSION);
        if !store_dir.exists() {
            return Ok(GcPreview {
                would_remove: Vec::new(),
                would_keep: 0,
                would_free_bytes: 0,
            });
        }

        let now = std::time::SystemTime::now();
        let mut would_remove = Vec::new();
        let mut would_keep = 0;
        let mut would_free_bytes: u64 = 0;

        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            let dir_name = entry.file_name().to_string_lossy().to_string();

            if let Some((pkg_name, version)) = complete_package_from_dir(&entry.path(), &dir_name) {
                let key = format!("{pkg_name}@{version}");

                if referenced.contains(&key) {
                    would_keep += 1;
                    continue;
                }

                // Check age filter
                if let Some(age_threshold) = max_age
                    && let Ok(meta) = entry.metadata()
                    && let Ok(mtime) = meta.modified()
                    && let Ok(elapsed) = now.duration_since(mtime)
                    && elapsed < *age_threshold
                {
                    would_keep += 1;
                    continue;
                }

                let size = dir_size(&entry.path());
                would_free_bytes += size;
                would_remove.push((key, size));
            }
        }

        would_remove.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(GcPreview {
            would_remove,
            would_keep,
            would_free_bytes,
        })
    }

    /// Remove a specific package from the store.
    pub fn remove_package(&self, name: &str, version: &str) -> Result<bool, LpmError> {
        let dir = self.package_dir(name, version);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn is_complete_package_dir(dir: &Path) -> bool {
    dir.is_dir() && dir.join("package.json").exists() && dir.join(".integrity").exists()
}

/// Phase 59.1 day-1 (F6) — strict validator for the local-tarball
/// CAS key.
///
/// Local tarballs use raw lowercase-hex SHA-256 (not an SRI string)
/// so the input can be sourced from `sha2::Sha256` digests directly
/// without an Integrity round-trip. Strict shape: exactly 64
/// characters, all `[0-9a-f]`. Case sensitivity is intentional —
/// uppercase hex would fork two store entries for the same content,
/// reintroducing the dedupe gap the CAS layer exists to close.
fn validate_sha256_hex(hex: &str) -> Result<(), LpmError> {
    if hex.len() != 64 {
        return Err(LpmError::InvalidIntegrity(format!(
            "expected 64 lowercase hex chars (SHA-256 digest), got {} chars",
            hex.len()
        )));
    }
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(LpmError::InvalidIntegrity(
            "expected 64 lowercase hex chars (SHA-256 digest), got non-hex or uppercase".into(),
        ));
    }
    Ok(())
}

fn is_temp_store_dir_name(dir_name: &str) -> bool {
    dir_name.contains(".tmp.")
}

fn complete_package_from_dir(dir: &Path, dir_name: &str) -> Option<(String, String)> {
    if !is_complete_package_dir(dir) || is_temp_store_dir_name(dir_name) {
        return None;
    }

    let at_pos = dir_name.rfind('@')?;
    let pkg_name = dir_name[..at_pos].replace('+', "/");
    let version = dir_name[at_pos + 1..].to_string();
    Some((pkg_name, version))
}

fn is_junk_store_dir(dir: &Path, dir_name: &str) -> bool {
    dir.is_dir()
        && (is_temp_store_dir_name(dir_name)
            || (dir_name.rfind('@').is_some() && !is_complete_package_dir(dir)))
}

/// Result of garbage collection.
#[derive(Debug)]
pub struct GcResult {
    pub removed: usize,
    pub kept: usize,
    pub freed_bytes: u64,
}

/// Preview of what garbage collection would remove (dry-run).
#[derive(Debug)]
pub struct GcPreview {
    /// Packages that would be removed: (name@version, size_bytes).
    pub would_remove: Vec<(String, u64)>,
    /// Number of packages that would be kept.
    pub would_keep: usize,
    /// Total bytes that would be freed.
    pub would_free_bytes: u64,
}

/// Compute an SRI (Subresource Integrity) hash for tarball data.
/// Format: `sha512-<base64>` (matches npm's integrity field format).
pub fn compute_sri_hash(data: &[u8]) -> String {
    use base64::Engine;
    let hash = Sha512::digest(data);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    format!("sha512-{b64}")
}

/// Read the stored `.integrity` file for a package.
/// Returns `None` if the file doesn't exist (package stored before integrity tracking).
pub fn read_stored_integrity(store_dir: &Path) -> Option<String> {
    let integrity_path = store_dir.join(".integrity");
    std::fs::read_to_string(integrity_path).ok()
}

/// Resolved location of a package's source bytes along with the
/// integrity SRI recorded for that copy. Returned by
/// [`find_installed_package_baseline`].
#[derive(Debug, Clone)]
pub struct InstalledPackageBaseline {
    /// Absolute path to the package directory whose contents match the
    /// extracted tarball. Under v1 this is `<store>/v1/<safe>@<ver>/`;
    /// under v2 this is `<store>/v2/links/<graph-key>/node_modules/<name>/`
    /// (the link's clonefile-materialized copy of the object-addressed
    /// bytes).
    pub package_dir: PathBuf,
    /// **Phase 66 confidence-followup F1 (2026-05-09)** — absolute path
    /// to a directory holding the **pristine, never-mutated** copy of
    /// the published bytes for `(name, version)`.
    ///
    /// - Under v1, equals [`Self::package_dir`]. The v1 store dir IS
    ///   pristine — patches mutate the project-private wrapper at
    ///   `<project>/.lpm/<seg>/node_modules/<name>/`, not the store
    ///   itself.
    /// - Under v2, points at `<store>/v2/objects/<sri-segment>/`. The
    ///   v2 link entry at `package_dir` IS the materialization
    ///   destination — patches written via `apply_patch` mutate it in
    ///   place. Reading patch baselines from `package_dir` under v2
    ///   would re-feed already-patched bytes to a second
    ///   `apply_patch` and break re-install idempotency.
    ///
    /// Read-only baseline consumers (the patch engine's pre-image
    /// reads, store-internal-file existence checks for ADD / DELETE
    /// hunks) MUST consult this field rather than `package_dir` to
    /// stay correct under both layouts.
    pub pristine_dir: PathBuf,
    /// SRI string of the source tarball — `meta.source_sri` under v2,
    /// `<package_dir>/.integrity` under v1.
    pub integrity: String,
    /// Which store the lookup hit. Callers that need to read sentinel
    /// files (e.g. `<v1_dir>/.integrity`) only when on v1 can branch on
    /// this.
    pub layout: PackageBaselineLayout,
}

/// Discriminator for [`InstalledPackageBaseline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageBaselineLayout {
    /// Package found at `<store>/v1/<safe>@<ver>/`.
    V1,
    /// Package found at `<store>/v2/links/<graph-key>/node_modules/<name>/`.
    V2,
}

/// **Phase 66 confidence-followup F2 (2026-05-09)** — invocation-local
/// index over the v2 store's link entries, keyed by `(name, version)`.
///
/// Built once per `lpm rebuild` / `lpm approve-scripts` /
/// `all_scripted_packages_trusted` / `scriptable_package_rows`
/// invocation from a SINGLE ordered walk of
/// [`crate::v2::Store::iter_link_entries`]. Subsequent per-package
/// lookups become O(1) hashmap reads instead of re-scanning every
/// link entry + parsing every sidecar JSON for each package the
/// caller asks about.
///
/// **Why this matters.** [`find_installed_package_baseline`] does an
/// O(N) scan + sidecar parse per call. The rebuild pipeline calls it
/// inside per-package loops over the lockfile (rebuild.rs:268-278,
/// rebuild.rs:1869, rebuild.rs:2069-2073). On a 1000-package lockfile
/// against a 5000-link global store that's 5M sidecar JSON reads per
/// invocation — pure waste, since the link-entry layout doesn't
/// change between iterations of one command.
///
/// **First-match semantics preserved.** When the same
/// `(name, version)` appears under multiple graph keys (multi-source-
/// same-coords or peer-divergent installs sharing coords), the
/// **first** entry seen in `iter_link_entries()` directory order
/// wins — exactly matching the legacy linear scan.
///
/// Construction is best-effort: malformed or unreadable sidecars are
/// silently skipped (same contract as `iter_link_entries`).
/// Constructing an empty index is cheap and safe — callers on stores
/// with no v2 entries (pure-v1 test fixtures, fresh installs pre-4b)
/// get an empty map and pay the v1-fallback cost only.
#[derive(Debug, Clone, Default)]
pub struct V2BaselineIndex {
    by_coords: std::collections::HashMap<(String, String), InstalledPackageBaseline>,
}

impl V2BaselineIndex {
    /// **Phase 66 confidence-followup F1+F2 review (2026-05-09)** —
    /// build a project-scoped index by walking only the link entries
    /// the project's `<project>/node_modules/` tree actually points
    /// at, BFS'd through each entry's `LinkMeta.deps` to cover
    /// transitives.
    ///
    /// **Why this exists.** [`Self::build`] (the global walker) keys
    /// on `(name, version)` and keeps the first match in directory
    /// iteration order. That tie-breaking was acceptable when v2
    /// could only have ONE link entry per coords by construction
    /// (the cross-project sharing invariant). After F1 a patched
    /// install lands in a distinct link entry from any unpatched
    /// install of the same coords, so two link entries for the
    /// same `(name, version)` legitimately coexist on disk —
    /// "first global match" is no longer a safe choice. The
    /// rebuild pipeline could otherwise read scripts / trust
    /// state / build-marker state from the wrong link entry,
    /// and write the build marker into a sibling project's store
    /// dir.
    ///
    /// **The walk.** Every entry under `<project>/node_modules/`
    /// that resolves to `<lpm_root>/store/v2/links/<key>/...` is a
    /// seed. From each seed link entry's [`LinkMeta::deps`], the
    /// dep's link-entry directory name is reconstructed
    /// (`{safe_name}@{version}+{first16hex}`) and visited too.
    /// Repeated until a fixed point is reached.
    ///
    /// **Safety.** Any sidecar that fails to parse, any symlink that
    /// points outside the v2 store, any non-symlink entry, and any
    /// reachable link entry whose `node_modules/<pkg>/` is missing
    /// is silently skipped. Each skip is logged at `tracing::debug!`
    /// so a malformed install surfaces under `RUST_LOG=debug`
    /// without blocking the operation.
    ///
    /// **Fallback contract.** When the project has no `node_modules/`
    /// (fresh checkout, never installed), or every symlink resolves
    /// outside the v2 store (pure-v1 install), this returns an empty
    /// index. Callers route through
    /// [`find_installed_package_baseline_indexed`] which falls
    /// through to the v1 lookup on miss — same behavior as a
    /// freshly-built [`Self::build`] empty index.
    pub fn for_project(
        project_dir: &std::path::Path,
        lpm_root: &lpm_common::LpmRoot,
    ) -> Result<Self, LpmError> {
        use std::collections::{HashSet, VecDeque};

        let store_v2 = crate::v2::Store::from_lpm_root(lpm_root);
        let links_root = store_v2.paths().links_root();
        let mut by_coords: std::collections::HashMap<(String, String), InstalledPackageBaseline> =
            std::collections::HashMap::new();

        // Seeds: every direct symlink under `<project>/node_modules/`
        // whose target lives inside `<links_root>/<key>/`.
        let mut to_visit: VecDeque<PathBuf> = VecDeque::new();
        let mut visited: HashSet<PathBuf> = HashSet::new();
        let nm_root = project_dir.join("node_modules");
        if let Ok(read_dir) = std::fs::read_dir(&nm_root) {
            for entry in read_dir.flatten() {
                let symlink_path = entry.path();
                seed_project_link_dir(&symlink_path, &links_root, &mut visited, &mut to_visit);

                // Scoped direct deps live at `node_modules/@scope/pkg`,
                // so the project root contains a REAL `@scope/` dir and
                // the symlink is one level deeper. Without this extra
                // walk, `for_project` misses every scoped direct dep.
                let file_type = match entry.file_type() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let is_scope_dir = file_type.is_dir()
                    && entry
                        .file_name()
                        .to_str()
                        .map(|name| name.starts_with('@'))
                        .unwrap_or(false);
                if !is_scope_dir {
                    continue;
                }

                if let Ok(scope_entries) = std::fs::read_dir(&symlink_path) {
                    for scope_entry in scope_entries.flatten() {
                        seed_project_link_dir(
                            &scope_entry.path(),
                            &links_root,
                            &mut visited,
                            &mut to_visit,
                        );
                    }
                }
            }
        }

        // BFS through each link entry's `LinkMeta.deps`. Sibling
        // entries are reached by reconstructing their directory name
        // from the dep's `target_graph_key` digest + name + version.
        while let Some(link_dir) = to_visit.pop_front() {
            let meta = match crate::v2::link_meta::LinkMeta::read_from(&link_dir) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(
                        "v2 project-scoped index: skipping {}: sidecar unreadable ({e})",
                        link_dir.display()
                    );
                    continue;
                }
            };
            // Trial 32: destructure meta to move name/version/source_sri
            // directly into the HashMap key + baseline without cloning.
            let crate::v2::link_meta::LinkMeta {
                name: meta_name,
                version: meta_version,
                source_sri: meta_sri,
                deps: meta_deps,
                ..
            } = meta;

            let package_dir = link_dir.join("node_modules").join(&meta_name);
            if !package_dir.exists() {
                tracing::debug!(
                    "v2 project-scoped index: skipping {}: package dir missing",
                    link_dir.display()
                );
                continue;
            }
            let pristine_dir = match store_v2.paths().object_dir(&meta_sri) {
                Ok(p) if p.exists() => p,
                _ => package_dir.clone(),
            };
            // Project-scoped: in a single project a (name, version) is
            // resolved by exactly one link entry, except the
            // multi-source-same-coords corner case (two distinct
            // sources sharing coords and BOTH symlinked from the
            // project — rare). Keep first-write-wins: the seed-symlink
            // walk inserts before the BFS, and BFS itself is FIFO, so
            // the chosen entry is whichever is closer to the project
            // root in the symlink graph.
            by_coords
                .entry((meta_name, meta_version))
                .or_insert(InstalledPackageBaseline {
                    package_dir,
                    pristine_dir,
                    integrity: meta_sri,
                    layout: PackageBaselineLayout::V2,
                });
            for dep in &meta_deps {
                // `LinkMeta.deps` carries the full 64-hex digest; the
                // on-disk dir name uses the first 16 chars. See
                // `crate::v2::GraphKey::dir_name` for the format.
                if dep.target_graph_key.len() < 16 {
                    continue; // malformed sidecar
                }
                let short_hex = &dep.target_graph_key[..16];
                // Trial 32: avoid allocating an intermediate safe_name
                // String for unscoped packages (the majority) by using
                // Cow<str> — borrows as-is when no replacement is needed.
                let safe_name: std::borrow::Cow<str> =
                    if dep.target_name.contains(['/', '\\']) {
                        std::borrow::Cow::Owned(dep.target_name.replace(['/', '\\'], "+"))
                    } else {
                        std::borrow::Cow::Borrowed(dep.target_name.as_str())
                    };
                let mut dep_dir_name =
                    String::with_capacity(safe_name.len() + 1 + dep.target_version.len() + 17);
                dep_dir_name.push_str(&safe_name);
                dep_dir_name.push('@');
                dep_dir_name.push_str(&dep.target_version);
                dep_dir_name.push('+');
                dep_dir_name.push_str(short_hex);
                let dep_link_dir = links_root.join(&dep_dir_name);
                if visited.insert(dep_link_dir.clone()) {
                    to_visit.push_back(dep_link_dir);
                }
            }
        }

        Ok(Self { by_coords })
    }

    /// Walk every v2 link entry under `lpm_root` once and produce an
    /// invocation-local lookup index.
    ///
    /// Returns `Ok(empty)` when v2 is empty or absent — callers should
    /// always succeed-then-fall-back via [`Self::lookup`], not gate on
    /// emptiness.
    ///
    /// **Use [`Self::for_project`] when the caller has a project
    /// directory in scope.** The global walk's first-match-wins
    /// tie-breaking is incorrect under post-F1 multi-link-per-coords
    /// states. `for_project` is the supported lookup path for
    /// `lpm rebuild` / `lpm approve-scripts` and any other read of
    /// project-side script state.
    pub fn build(lpm_root: &lpm_common::LpmRoot) -> Result<Self, LpmError> {
        let store_v2 = crate::v2::Store::from_lpm_root(lpm_root);
        let mut by_coords: std::collections::HashMap<(String, String), InstalledPackageBaseline> =
            std::collections::HashMap::new();
        for (link_dir, meta) in store_v2.iter_link_entries()? {
            let key = (meta.name.clone(), meta.version.clone());
            // First-match wins. `iter_link_entries` returns directory
            // order, which matches the legacy linear scan's
            // tie-breaking. Re-running this walk twice on the same
            // disk state must produce the same map; that's why we
            // skip the insert when a coord is already populated
            // rather than overwrite.
            if by_coords.contains_key(&key) {
                continue;
            }
            let package_dir = link_dir.join("node_modules").join(&meta.name);
            if !package_dir.exists() {
                // Sidecar present but link entry missing the package
                // dir — corrupt entry. Skip and let any later valid
                // entry for the same coords win, mirroring
                // `find_installed_package_baseline`.
                continue;
            }
            let pristine_dir = match store_v2.paths().object_dir(&meta.source_sri) {
                Ok(p) if p.exists() => p,
                _ => package_dir.clone(),
            };
            by_coords.insert(
                key,
                InstalledPackageBaseline {
                    package_dir,
                    pristine_dir,
                    integrity: meta.source_sri,
                    layout: PackageBaselineLayout::V2,
                },
            );
        }
        Ok(Self { by_coords })
    }

    /// O(1) lookup. `None` means no v2 link entry covers the
    /// `(name, version)` pair — caller should fall back to v1.
    pub fn lookup(&self, name: &str, version: &str) -> Option<&InstalledPackageBaseline> {
        self.by_coords.get(&(name.to_string(), version.to_string()))
    }
}

fn seed_project_link_dir(
    symlink_path: &Path,
    links_root: &Path,
    visited: &mut std::collections::HashSet<PathBuf>,
    to_visit: &mut std::collections::VecDeque<PathBuf>,
) {
    // `read_link` reads the symlink target without following further
    // symlinks. v2 plants ABSOLUTE symlinks at the project root today,
    // but nested scoped entries should still resolve relative to their
    // own parent dir if that ever changes.
    let target = match std::fs::read_link(symlink_path) {
        Ok(t) => t,
        Err(_) => return,
    };
    let target = if target.is_absolute() {
        target
    } else {
        symlink_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(target)
    };
    if let Some(link_dir) = link_dir_from_target(&target, links_root)
        && visited.insert(link_dir.clone())
    {
        to_visit.push_back(link_dir);
    }
}

/// **Phase 66 confidence-followup F1+F2 review** — given a path that a
/// project-side symlink resolves to, reconstruct the v2 link entry
/// directory that owns it.
///
/// v2 plants the project's `<project>/node_modules/<dep>` symlink to
/// point at `<links_root>/<key_dir>/node_modules/<dep>/`. Scoped deps
/// add one more segment (`node_modules/@scope/<pkg>/`). Rather than
/// trying to strip a fixed suffix width, walk ancestors until the
/// first path whose parent is exactly `<links_root>` — that ancestor
/// is the owning `<key_dir>` for both unscoped and scoped targets.
/// Returns `None` when the target lives outside `links_root` (e.g. a
/// project-local file:/link: dep, a v1-installed package with a
/// custom symlink shape, or a legitimately-broken symlink).
///
/// Uses ancestor walking + path-prefix matching rather than canonical-
/// izing both paths, so a non-canonical `links_root` (test fixture
/// with `/private/var/.../links/...` vs `/var/.../links/...` on macOS)
/// still matches when the input target is canonical.
fn link_dir_from_target(target: &Path, links_root: &Path) -> Option<PathBuf> {
    for ancestor in target.ancestors() {
        if ancestor.parent() == Some(links_root) {
            return Some(ancestor.to_path_buf());
        }
    }
    // macOS canonicalization mismatch fallback: if direct parent
    // comparison missed, check via `starts_with` against the
    // canonicalized links_root. Symmetric with `iter_link_entries`'
    // tolerance for paths.
    let canonical_links_root = match links_root.canonicalize() {
        Ok(p) => p,
        Err(_) => return None,
    };
    let canonical_target = match target.canonicalize() {
        Ok(p) => p,
        Err(_) => return None,
    };
    for ancestor in canonical_target.ancestors() {
        if ancestor.parent() == Some(canonical_links_root.as_path()) {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

/// Index-aware variant of [`find_installed_package_baseline`]. Hits
/// the pre-built [`V2BaselineIndex`] for v2 in O(1); falls back to
/// the same v1 lookup as the legacy helper on a v2 miss. Returns
/// `None` when neither store has the package — same shape as the
/// `Result<Option<…>, _>` of the legacy call, except construction
/// errors are absorbed at index-build time so per-package callers
/// don't have to thread a `Result` through hot loops.
pub fn find_installed_package_baseline_indexed(
    index: &V2BaselineIndex,
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
) -> Option<InstalledPackageBaseline> {
    if let Some(b) = index.lookup(name, version) {
        return Some(b.clone());
    }
    let store_v1 = PackageStore::from_root(lpm_root);
    let pkg_dir = store_v1.package_dir(name, version);
    if pkg_dir.exists()
        && let Some(integrity) = read_stored_integrity(&pkg_dir)
    {
        return Some(InstalledPackageBaseline {
            package_dir: pkg_dir.clone(),
            pristine_dir: pkg_dir,
            integrity,
            layout: PackageBaselineLayout::V1,
        });
    }
    None
}

/// Resolve a package's installed source bytes + integrity in a
/// store-version-agnostic way. **Prefers v2** (the active default
/// since Phase 66 4b); falls back to v1 if no v2 link entry matches.
///
/// Designed for downstream commands that read package metadata or
/// source files post-install — `lpm patch`, `lpm patch-commit`,
/// `lpm rebuild`, `lpm approve-scripts --show-scripts`, etc. — which
/// must not blindly call [`PackageStore::package_dir`] (v1-only)
/// under v2 installs.
///
/// **Multi-source-same-coords:** under Phase 66 §2.2, two distinct
/// sources can share the same `(name, version)` pair and produce
/// different graph keys. This helper picks the first v2 link entry
/// that matches in `iter_link_entries` directory order. That's
/// non-deterministic for multi-source-same-coords + lifecycle
/// scripts, but acceptable for the patch path (the user's patch is
/// keyed on `<name>@<version>` and should apply equally to every
/// graph-key sharing those coords). A future refinement is a full
/// `(name, version, wrapper_id)` lookup once `wrapper_id` is
/// threaded through the lockfile — same follow-up
/// [`crate::v2::Store::find_link_package_dir`] documents.
pub fn find_installed_package_baseline(
    lpm_root: &lpm_common::LpmRoot,
    name: &str,
    version: &str,
) -> Result<Option<InstalledPackageBaseline>, LpmError> {
    // v2 first — that's the default since Phase 66 4b. Iterating link
    // entries reads each sidecar `.lpm-link-meta.json`; the iterator
    // gracefully skips malformed entries (per
    // [`crate::v2::Store::iter_link_entries`]'s docs) so a corrupt
    // sibling never blocks a valid match.
    let store_v2 = crate::v2::Store::from_lpm_root(lpm_root);
    for (link_dir, meta) in store_v2.iter_link_entries()? {
        if meta.name == name && meta.version == version {
            let package_dir = link_dir.join("node_modules").join(name);
            if package_dir.exists() {
                // F1: derive the pristine object dir from the source SRI.
                // Phase 66 4b populates link entries via clonefile from
                // `objects/<sri>/`, so for a well-formed install the
                // object dir is always derivable AND present on disk.
                //
                // **Defensive aliasing.** If either `sri_to_segment`
                // can't parse the SRI (synthetic test fixtures) or
                // the resolved path is missing on disk (manual
                // pruning, partial migration), fall back to aliasing
                // `package_dir`. Patch consumers will then re-read
                // the link entry directly — same shape as v1, where
                // `pristine_dir == package_dir` by construction. A
                // genuinely-corrupt v2 install fails later with a
                // patch-engine drift error rather than swallowing
                // the lookup here, which keeps the user-facing
                // failure mode close to the cause.
                let pristine_dir = match store_v2.paths().object_dir(&meta.source_sri) {
                    Ok(p) if p.exists() => p,
                    _ => package_dir.clone(),
                };
                return Ok(Some(InstalledPackageBaseline {
                    package_dir,
                    pristine_dir,
                    integrity: meta.source_sri,
                    layout: PackageBaselineLayout::V2,
                }));
            }
            // The sidecar pointed at us, but the materialized package
            // dir is missing — corrupt link entry. Continue scanning
            // for another link that might satisfy the request.
        }
    }
    // v1 fallback — older installs, the migration grace window, or
    // ad-hoc test fixtures that populate v1 directly.
    let store_v1 = PackageStore::from_root(lpm_root);
    let pkg_dir = store_v1.package_dir(name, version);
    if pkg_dir.exists()
        && let Some(integrity) = read_stored_integrity(&pkg_dir)
    {
        return Ok(Some(InstalledPackageBaseline {
            package_dir: pkg_dir.clone(),
            // F1: under v1 the store dir IS pristine — patches mutate
            // project-private wrappers, never the v1 store. Aliasing
            // the same path here keeps the patch engine layout-agnostic
            // (read pristine bytes from `pristine_dir`, write
            // destinations via `MaterializedPackage.destination`).
            pristine_dir: pkg_dir,
            integrity,
            layout: PackageBaselineLayout::V1,
        }));
    }
    Ok(None)
}

/// Phase 38 P1 helper: transparent `Read` wrapper that feeds every byte
/// into a SHA-512 hasher as it flows through. Used to compute the tarball
/// SRI inline with streaming extraction, no second pass, no temp file.
///
/// After the extractor finishes consuming the stream, call
/// [`HashingReader::finalize`] to obtain `(sri_string, bytes_seen)`.
struct HashingReader<R> {
    inner: R,
    hasher: Sha512,
    bytes: u64,
}

impl<R: std::io::Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha512::new(),
            bytes: 0,
        }
    }

    /// Finalize the hash and return `(sri, total_bytes_read)`.
    /// Consumes `self` because the hasher is one-shot.
    fn finalize(self) -> (String, u64) {
        use base64::Engine;
        let digest = self.hasher.finalize();
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        (sri, self.bytes)
    }
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.bytes += n as u64;
        }
        Ok(n)
    }
}

/// Phase 38 P1 helper: caps total bytes read to `limit`. Tripping the
/// limit returns `ErrorKind::InvalidData` with a message mirroring the
/// legacy `download_tarball_to_file` rejection, which then surfaces
/// through the extractor as a regular `LpmError::Io`. No bytes past the
/// cap are ever written to the staging directory.
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

/// Calculate the total size of a directory recursively.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };

            if meta.file_type().is_symlink() {
                total += meta.len();
            } else if meta.is_dir() {
                total += dir_size(&path);
            } else {
                total += meta.len();
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn create_test_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("package/{path}"), &content[..])
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

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
        // Second call should be a cache hit
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
        // Directory name should not contain / or @
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

        // Second store of same package should hit the fast path
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
    fn list_packages() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);

        store.store_package("alpha", "1.0.0", &tarball).unwrap();
        store.store_package("beta", "2.0.0", &tarball).unwrap();

        let list = store.list_packages().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], ("alpha".to_string(), "1.0.0".to_string()));
        assert_eq!(list[1], ("beta".to_string(), "2.0.0".to_string()));
    }

    #[test]
    fn list_packages_ignores_temp_and_incomplete_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);

        store.store_package("valid", "1.0.0", &tarball).unwrap();

        let store_v1 = dir.path().join("v1");
        let stale_tmp = store_v1.join("valid@1.0.0.tmp.stale");
        std::fs::create_dir_all(&stale_tmp).unwrap();
        std::fs::write(stale_tmp.join("package.json"), b"{}").unwrap();
        std::fs::write(stale_tmp.join(".integrity"), b"sha512-stale").unwrap();

        let incomplete = store_v1.join("broken@1.0.0");
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("package.json"), b"{}").unwrap();

        let list = store.list_packages().unwrap();

        assert_eq!(list, vec![("valid".to_string(), "1.0.0".to_string())]);
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

        // .integrity file should exist
        let integrity_path = path.join(".integrity");
        assert!(integrity_path.exists(), ".integrity file must be written");

        let stored = std::fs::read_to_string(&integrity_path).unwrap();
        assert!(
            stored.starts_with("sha512-"),
            "integrity must be SRI format"
        );

        // Verify it matches a fresh computation
        let expected = compute_sri_hash(&tarball);
        assert_eq!(stored, expected);
    }

    #[test]
    fn read_stored_integrity_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_stored_integrity(dir.path()).is_none());
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

        // .lpm-security.json should exist
        let security_path = path.join(".lpm-security.json");
        assert!(
            security_path.exists(),
            ".lpm-security.json must be written during extraction"
        );

        // Parse and verify contents
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

        // First store — writes analysis
        let path1 = store.store_package("cached", "1.0.0", &tarball).unwrap();
        assert!(path1.join(".lpm-security.json").exists());

        // Second store — cache hit, should still have the file
        let path2 = store.store_package("cached", "1.0.0", &tarball).unwrap();
        assert!(path2.join(".lpm-security.json").exists());

        // Verify analysis is readable via the public API
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

        // Tamper with the integrity file
        std::fs::write(path.join(".integrity"), "sha512-TAMPERED").unwrap();

        let stored = read_stored_integrity(&path).unwrap();
        let expected = compute_sri_hash(&tarball);
        assert_ne!(stored, expected, "tampered integrity should not match");
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

        // Final directory must be valid
        let store = PackageStore::at(dir.path());
        assert!(store.has_package("race", "1.0.0"));
        let pkg_dir = store.package_dir("race", "1.0.0");
        assert!(pkg_dir.join("package.json").exists());
        assert!(pkg_dir.join("index.js").exists());

        // No stale .tmp directories should remain
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

    // ─── Garbage collection tests ──────────────────────────────────────

    #[test]
    fn gc_removes_unreferenced_packages() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("keep", "1.0.0", &tarball).unwrap();
        store.store_package("remove", "1.0.0", &tarball).unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("keep@1.0.0".to_string());

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, 1);
        assert_eq!(result.kept, 1);
        assert!(result.freed_bytes > 0);
        assert!(store.has_package("keep", "1.0.0"));
        assert!(!store.has_package("remove", "1.0.0"));
    }

    #[test]
    fn gc_keeps_all_referenced_packages() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("a", "1.0.0", &tarball).unwrap();
        store.store_package("b", "2.0.0", &tarball).unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("a@1.0.0".to_string());
        referenced.insert("b@2.0.0".to_string());

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, 0);
        assert_eq!(result.kept, 2);
        assert_eq!(result.freed_bytes, 0);
    }

    #[test]
    fn gc_empty_store_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let referenced = std::collections::HashSet::new();
        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, 0);
        assert_eq!(result.kept, 0);
    }

    #[test]
    fn gc_preview_matches_actual_removal() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"pkg\"}"),
            ("index.js", b"module.exports = 1"),
        ]);
        store.store_package("pkg", "1.0.0", &tarball).unwrap();
        store.store_package("pkg", "2.0.0", &tarball).unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("pkg@2.0.0".to_string());

        let preview = store.gc_preview(&referenced, None).unwrap();
        assert_eq!(preview.would_remove.len(), 1);
        assert_eq!(preview.would_keep, 1);
        assert!(preview.would_free_bytes > 0);

        // Now actually GC and verify counts match
        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(result.removed, preview.would_remove.len());
        assert_eq!(result.kept, preview.would_keep);
        assert_eq!(result.freed_bytes, preview.would_free_bytes);
    }

    #[test]
    fn gc_respects_max_age_keeps_recent() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("recent", "1.0.0", &tarball).unwrap();

        // Package was just created — mtime is now. With a 30-day threshold,
        // it should be kept even though it's unreferenced.
        let referenced = std::collections::HashSet::new();
        let max_age = std::time::Duration::from_secs(30 * 86400);

        let result = store.gc(&referenced, Some(&max_age)).unwrap();
        assert_eq!(result.removed, 0, "recently created package should be kept");
        assert_eq!(result.kept, 1);
        assert!(store.has_package("recent", "1.0.0"));
    }

    #[test]
    fn gc_scoped_package_name_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store
            .store_package("@scope/pkg", "1.0.0", &tarball)
            .unwrap();

        // Reference with the original scoped name (not the filesystem-safe name)
        let mut referenced = std::collections::HashSet::new();
        referenced.insert("@scope/pkg@1.0.0".to_string());

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(
            result.removed, 0,
            "scoped package should match by original name"
        );
        assert_eq!(result.kept, 1);
    }

    #[test]
    fn gc_preview_doesnt_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("doomed", "1.0.0", &tarball).unwrap();

        let referenced = std::collections::HashSet::new();
        let preview = store.gc_preview(&referenced, None).unwrap();

        assert_eq!(preview.would_remove.len(), 1);
        // But the package should still be there
        assert!(
            store.has_package("doomed", "1.0.0"),
            "preview should not delete"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gc_preview_does_not_count_external_symlink_target_bytes() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let package_dir = store.package_dir("linked", "1.0.0");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(
            package_dir.join("package.json"),
            br#"{"name":"linked","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(package_dir.join(".integrity"), b"sha512-linked").unwrap();

        let external_file = dir.path().join("outside.bin");
        let external_size = 32 * 1024;
        std::fs::write(&external_file, vec![b'x'; external_size]).unwrap();
        symlink(&external_file, package_dir.join("external-link")).unwrap();

        let referenced = std::collections::HashSet::new();
        let preview = store.gc_preview(&referenced, None).unwrap();

        assert_eq!(preview.would_remove.len(), 1);
        assert_eq!(preview.would_remove[0].0, "linked@1.0.0");
        assert!(
            preview.would_free_bytes < external_size as u64,
            "gc preview should not count bytes from symlink targets outside the store"
        );
    }

    #[test]
    fn gc_skips_junk_in_preview_and_removes_it_during_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        store.store_package("keep", "1.0.0", &tarball).unwrap();

        let store_v1 = dir.path().join("v1");
        let stale_tmp = store_v1.join("keep@1.0.0.tmp.stale");
        std::fs::create_dir_all(&stale_tmp).unwrap();
        std::fs::write(stale_tmp.join("package.json"), b"{}").unwrap();
        std::fs::write(stale_tmp.join(".integrity"), b"sha512-stale").unwrap();

        let incomplete = store_v1.join("broken@1.0.0");
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("package.json"), b"{}").unwrap();

        let mut referenced = std::collections::HashSet::new();
        referenced.insert("keep@1.0.0".to_string());

        let preview = store.gc_preview(&referenced, None).unwrap();
        assert!(
            preview.would_remove.is_empty(),
            "junk dirs should not appear as removable packages"
        );
        assert_eq!(
            preview.would_keep, 1,
            "only complete referenced packages should count as kept"
        );

        let result = store.gc(&referenced, None).unwrap();
        assert_eq!(
            result.removed, 0,
            "junk cleanup should not be counted as package removal"
        );
        assert_eq!(
            result.kept, 1,
            "only complete referenced packages should count as kept"
        );
        assert!(store.has_package("keep", "1.0.0"));
        assert!(
            !stale_tmp.exists(),
            "gc should clean stale temp directories"
        );
        assert!(
            !incomplete.exists(),
            "gc should clean incomplete directories"
        );
    }

    // ─── File-based store tests ──────────────────────────────────────

    #[test]
    fn store_from_file_creates_package() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tgz = create_test_tarball(&[
            ("package.json", br#"{"name":"file-test","version":"1.0.0"}"#),
            ("index.js", b"exports.run = () => 'file-based'"),
        ]);

        // Write tarball to a temp file
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut temp, &tgz).unwrap();

        let sri = "sha512-test-hash";
        let path = store
            .store_package_from_file("file-test", "1.0.0", temp.path(), sri)
            .unwrap();

        assert!(store.has_package("file-test", "1.0.0"));
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());

        // Verify .integrity was written with the provided SRI
        let stored_sri = std::fs::read_to_string(path.join(".integrity")).unwrap();
        assert_eq!(stored_sri, sri);
    }

    #[test]
    fn store_from_file_cache_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tgz =
            create_test_tarball(&[("package.json", br#"{"name":"cached","version":"1.0.0"}"#)]);

        // First store via memory path
        store.store_package("cached", "1.0.0", &tgz).unwrap();
        assert!(store.has_package("cached", "1.0.0"));

        // Second store via file path — should hit cache
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
        // No stale temp dirs left
        let store_v1 = store.root.join("v1");
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

    // ── Phase 59.0 day-4 (F4): tarball CAS path ─────────────────────────────

    fn sha512_sri(body: &[u8]) -> String {
        Integrity::from_bytes(HashAlgorithm::Sha512, body).to_string()
    }

    fn sha256_sri(body: &[u8]) -> String {
        Integrity::from_bytes(HashAlgorithm::Sha256, body).to_string()
    }

    #[test]
    fn tarball_store_path_under_versioned_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let path = store.tarball_store_path(&sha512_sri(b"x")).unwrap();
        // Lives under the v1/ root + tarball/ subtree, distinct from
        // the registry arm's `v1/{name}@{version}/` layout.
        let expected_prefix = dir.path().join(STORE_VERSION).join("tarball");
        assert!(
            path.starts_with(&expected_prefix),
            "expected prefix {:?}, got {:?}",
            expected_prefix,
            path,
        );
    }

    #[test]
    fn tarball_store_path_filename_is_filesystem_safe() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let path = store
            .tarball_store_path(&sha512_sri(b"hello world"))
            .unwrap();
        let leaf = path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("leaf must be utf-8");
        // No '/', '+', or '=' — those break filesystem semantics
        // or are unsanitary in path components on Windows.
        assert!(!leaf.contains('/'), "got {leaf:?}");
        assert!(!leaf.contains('+'), "got {leaf:?}");
        assert!(!leaf.contains('='), "got {leaf:?}");
        assert!(leaf.starts_with("sha512-"), "got {leaf:?}");
        // sha512-<128 hex chars> = 7 + 128 = 135 chars
        assert_eq!(leaf.len(), 7 + 128, "got {leaf:?}");
        // After the prefix, only hex.
        assert!(leaf[7..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tarball_store_path_distinguishes_algorithms() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let body = b"same content, different algo";
        let p256 = store.tarball_store_path(&sha256_sri(body)).unwrap();
        let p512 = store.tarball_store_path(&sha512_sri(body)).unwrap();
        // Same body, different algorithms → distinct CAS paths so a
        // sha256-declared dep can't accidentally collide with a
        // sha512-declared dep on the same content.
        assert_ne!(p256, p512);
        assert!(
            p256.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sha256-")
        );
        assert!(
            p512.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sha512-")
        );
        // sha256 path = 7 + 64 hex chars
        assert_eq!(p256.file_name().unwrap().to_string_lossy().len(), 7 + 64);
    }

    #[test]
    fn tarball_store_path_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let sri = sha512_sri(b"stable content");
        let p1 = store.tarball_store_path(&sri).unwrap();
        let p2 = store.tarball_store_path(&sri).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn tarball_store_path_distinguishes_content() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let p1 = store.tarball_store_path(&sha512_sri(b"first")).unwrap();
        let p2 = store.tarball_store_path(&sha512_sri(b"second")).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn tarball_store_path_rejects_invalid_sri() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        // Missing algorithm prefix.
        assert!(store.tarball_store_path("not-a-real-sri").is_err());
        // Unsupported algorithm.
        assert!(store.tarball_store_path("md5-deadbeef").is_err());
        // Non-base64 hash body.
        assert!(store.tarball_store_path("sha512-!!!").is_err());
    }

    #[test]
    fn has_tarball_returns_false_when_dir_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        assert!(!store.has_tarball(&sha512_sri(b"never stored")));
    }

    #[test]
    fn has_tarball_returns_false_for_invalid_sri() {
        // Mirrors has_package: invalid input → false (don't propagate
        // an error from a query method that callers expect to be
        // total).
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        assert!(!store.has_tarball("not-a-real-sri"));
    }

    // ── Phase 59.0 day-5: store_tarball_at_cas_path ─────────────────────────

    #[test]
    fn store_tarball_at_cas_path_extracts_to_cas_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"foo\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 42"),
        ]);
        let sri = sha512_sri(&tarball);

        assert!(!store.has_tarball(&sri));

        let path = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        assert!(store.has_tarball(&sri));
        // Path equals the public CAS path getter for the same SRI.
        assert_eq!(path, store.tarball_store_path(&sri).unwrap());
        // Files extracted into the CAS dir.
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());
    }

    #[test]
    fn store_tarball_at_cas_path_writes_integrity_file() {
        // Same .integrity post-extraction contract as store_package
        // (the shared store_at_dir helper). Required for
        // `store verify --deep` to detect post-extraction tampering.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let sri = sha512_sri(&tarball);
        let path = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        assert!(path.join(".integrity").exists());
    }

    #[test]
    fn store_tarball_at_cas_path_runs_security_analysis() {
        // .lpm-security.json must be present at extraction time so
        // the install path's security gate has the analysis cache
        // ready before linking.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let sri = sha512_sri(&tarball);
        let path = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        assert!(path.join(".lpm-security.json").exists());
    }

    #[test]
    fn store_tarball_at_cas_path_cache_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let sri = sha512_sri(&tarball);

        let path1 = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        let mtime1 = std::fs::metadata(path1.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();

        // Second call must hit the existing CAS dir and skip
        // extraction. We verify by mtime — a re-extract would
        // bump the package.json mtime.
        let path2 = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        assert_eq!(path1, path2);
        let mtime2 = std::fs::metadata(path2.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime1, mtime2, "second call must not re-extract");
    }

    #[test]
    fn store_tarball_at_cas_path_rejects_invalid_sri() {
        // Mirrors tarball_store_path's contract: parsing failure
        // surfaces as InvalidIntegrity rather than running through
        // extraction.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        assert!(
            store
                .store_tarball_at_cas_path("not-a-real-sri", &tarball)
                .is_err()
        );
    }

    #[test]
    fn store_tarball_at_cas_path_distinct_content_distinct_paths() {
        // Two different tarballs (different content) get distinct
        // CAS slots — F4 identity correctness.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball_a = create_test_tarball(&[("a.js", b"alpha")]);
        let tarball_b = create_test_tarball(&[("b.js", b"beta")]);
        let sri_a = sha512_sri(&tarball_a);
        let sri_b = sha512_sri(&tarball_b);
        assert_ne!(sri_a, sri_b);

        let path_a = store.store_tarball_at_cas_path(&sri_a, &tarball_a).unwrap();
        let path_b = store.store_tarball_at_cas_path(&sri_b, &tarball_b).unwrap();
        assert_ne!(path_a, path_b);
        assert!(path_a.join("a.js").exists());
        assert!(path_b.join("b.js").exists());
        // No leakage either way.
        assert!(!path_a.join("b.js").exists());
        assert!(!path_b.join("a.js").exists());
    }

    #[test]
    fn store_tarball_at_cas_path_does_not_collide_with_registry_arm() {
        // The Registry arm uses `v1/{name}@{version}/` and the
        // Tarball arm uses `v1/tarball/{algo}-{hex}/` — two distinct
        // subtrees under the shared STORE_VERSION root. F4 identity
        // protection: a registry package and a tarball-source
        // package with the same content never share a slot.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let sri = sha512_sri(&tarball);

        let registry_path = store.store_package("foo", "1.0.0", &tarball).unwrap();
        let tarball_path = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();

        assert_ne!(registry_path, tarball_path);
        // Both exist independently (no co-location).
        assert!(registry_path.exists());
        assert!(tarball_path.exists());
    }

    // ── Phase 59.1 day-1 (F6): tarball-local CAS path ───────────────────────

    fn sha256_hex(body: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(body);
        format!("{:x}", h.finalize())
    }

    #[test]
    fn tarball_local_store_path_under_versioned_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let path = store.tarball_local_store_path(&sha256_hex(b"x")).unwrap();
        // Lives under v1/tarball-local/, distinct from both the
        // Registry arm (`v1/{name}@{version}/`) and the remote-tarball
        // arm (`v1/tarball/{algo}-{hex}/`). Carving a parallel subtree
        // under the shared v1 root keeps a future schema bump atomic
        // across all source kinds.
        let expected_prefix = dir.path().join(STORE_VERSION).join("tarball-local");
        assert!(
            path.starts_with(&expected_prefix),
            "expected prefix {:?}, got {:?}",
            expected_prefix,
            path,
        );
    }

    #[test]
    fn tarball_local_store_path_filename_is_filesystem_safe() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let path = store
            .tarball_local_store_path(&sha256_hex(b"hello"))
            .unwrap();
        let leaf = path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("leaf must be utf-8");
        assert!(leaf.starts_with("sha256-"), "got {leaf:?}");
        // sha256-<64 hex chars> = 7 + 64 = 71 chars
        assert_eq!(leaf.len(), 7 + 64, "got {leaf:?}");
        assert!(leaf[7..].chars().all(|c| c.is_ascii_hexdigit()));
        // Lowercase only (uppercase would fork dedupe).
        assert!(leaf[7..].chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn tarball_local_store_path_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let hex = sha256_hex(b"stable content");
        let p1 = store.tarball_local_store_path(&hex).unwrap();
        let p2 = store.tarball_local_store_path(&hex).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn tarball_local_store_path_distinguishes_content() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let p1 = store
            .tarball_local_store_path(&sha256_hex(b"first"))
            .unwrap();
        let p2 = store
            .tarball_local_store_path(&sha256_hex(b"second"))
            .unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn tarball_local_store_path_rejects_invalid_input() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        // Wrong length (63 chars).
        assert!(
            store
                .tarball_local_store_path(
                    "deadbeef00000000000000000000000000000000000000000000000000000000"[..63]
                        .as_ref(),
                )
                .is_err()
        );
        // Wrong length (65 chars).
        assert!(
            store
                .tarball_local_store_path(
                    "deadbeef000000000000000000000000000000000000000000000000000000000",
                )
                .is_err()
        );
        // Uppercase hex (would fork dedupe).
        assert!(
            store
                .tarball_local_store_path(
                    "DEADBEEF00000000000000000000000000000000000000000000000000000000",
                )
                .is_err()
        );
        // Non-hex characters.
        assert!(
            store
                .tarball_local_store_path(
                    "zzzzzzzz00000000000000000000000000000000000000000000000000000000",
                )
                .is_err()
        );
        // SRI shape (not raw hex) — sha256-<base64> would slip past a
        // length check; assert the strict-hex validator catches it.
        assert!(
            store
                .tarball_local_store_path("sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",)
                .is_err()
        );
    }

    #[test]
    fn tarball_local_does_not_collide_with_remote_tarball_arm() {
        // Remote tarball CAS: `v1/tarball/{algo}-{hex}/`.
        // Local tarball CAS: `v1/tarball-local/sha256-{hex}/`.
        // Distinct subtrees: a remote SHA-256-keyed tarball and a
        // local tarball with bytes that hash to the same SHA-256 land
        // in different slots. F6 identity correctness — local tarball
        // identity is content-only (no URL); remote tarball identity
        // includes the URL via `Source::Tarball { url }`. Sharing a
        // CAS slot would let `lpm update` silently swap one for the
        // other.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let body = b"identical bytes";
        let remote = store.tarball_store_path(&sha256_sri(body)).unwrap();
        let local = store.tarball_local_store_path(&sha256_hex(body)).unwrap();
        assert_ne!(remote, local);
        assert!(
            remote
                .ancestors()
                .any(|p| p.file_name().is_some_and(|n| n == "tarball")),
            "remote tarball must live under v1/tarball/, got {remote:?}",
        );
        assert!(
            local
                .ancestors()
                .any(|p| p.file_name().is_some_and(|n| n == "tarball-local")),
            "local tarball must live under v1/tarball-local/, got {local:?}",
        );
    }

    #[test]
    fn has_local_tarball_returns_false_when_dir_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        assert!(!store.has_local_tarball(&sha256_hex(b"never stored")));
    }

    #[test]
    fn has_local_tarball_returns_false_for_invalid_hex() {
        // Mirrors has_tarball: invalid input → false (don't propagate
        // an error from a query method that callers expect to be
        // total).
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        assert!(!store.has_local_tarball("not-a-real-hex"));
    }

    // ── Phase 59.1 day-1 (F6): store_local_tarball_at_cas_path ──────────────

    #[test]
    fn store_local_tarball_at_cas_path_extracts_to_cas_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"local-foo\",\"version\":\"1.0.0\"}",
            ),
            ("index.js", b"module.exports = 42"),
        ]);
        let hex = sha256_hex(&tarball);

        assert!(!store.has_local_tarball(&hex));

        let path = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        assert!(store.has_local_tarball(&hex));
        assert_eq!(path, store.tarball_local_store_path(&hex).unwrap());
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());
    }

    #[test]
    fn store_local_tarball_at_cas_path_writes_integrity_and_security() {
        // Same .integrity and .lpm-security.json post-extraction
        // contract as the registry/remote-tarball arms — shared via
        // the private store_at_dir helper.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let hex = sha256_hex(&tarball);
        let path = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        assert!(path.join(".integrity").exists());
        assert!(path.join(".lpm-security.json").exists());
    }

    #[test]
    fn store_local_tarball_at_cas_path_cache_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let hex = sha256_hex(&tarball);

        let path1 = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        let mtime1 = std::fs::metadata(path1.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();
        let path2 = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        assert_eq!(path1, path2);
        let mtime2 = std::fs::metadata(path2.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime1, mtime2, "second call must not re-extract");
    }

    #[test]
    fn store_local_tarball_at_cas_path_rejects_invalid_hex() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        assert!(
            store
                .store_local_tarball_at_cas_path("not-a-real-hex", &tarball)
                .is_err()
        );
    }

    #[test]
    fn store_local_tarball_at_cas_path_dedupes_same_content() {
        // Two consumers using `file:./a.tgz` and `file:../shared/a.tgz`
        // of the same bytes share one extracted store dir — the
        // content-keyed CAS contract for F6. (Identity is content-only
        // for local tarballs; the URL/path is not part of the key.)
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"shared\",\"version\":\"1.0.0\"}",
        )]);
        let hex = sha256_hex(&tarball);

        // Consumer A extracts.
        let path_a = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        // Consumer B with the same bytes from a different file: path
        // hits the same CAS slot. (Caller-supplied hex is the key —
        // the path it came from never enters the helper.)
        let path_b = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        assert_eq!(path_a, path_b);
    }

    // ── Phase 66 Phase 4d — StoreVersion env-var parser ─────────

    #[test]
    fn store_version_default_is_v2() {
        // Phase 4d flipped the default from v1 → v2. Pre-flip the
        // default was v1 (dev-only opt-in for v2).
        assert_eq!(StoreVersion::default(), StoreVersion::V2);
    }

    #[test]
    fn store_version_parse_unset_is_v2() {
        // Unset env var yields the new v2 default.
        assert_eq!(StoreVersion::parse(None), StoreVersion::V2);
    }

    #[test]
    fn store_version_parse_recognizes_v2_aliases() {
        // Empty string normalizes to v2 (the post-Phase-4d default).
        for s in ["", "v2", "V2", "2", "  V2  ", "v2\n"] {
            assert_eq!(
                StoreVersion::parse(Some(s)),
                StoreVersion::V2,
                "input {s:?} should resolve to v2"
            );
        }
    }

    #[test]
    fn store_version_parse_recognizes_v1_downgrade_aliases() {
        // Phase 4d retains v1 as an explicit downgrade-rollback path.
        for s in ["v1", "V1", "1", "  v1  "] {
            assert_eq!(
                StoreVersion::parse(Some(s)),
                StoreVersion::V1,
                "input {s:?} should resolve to v1 (explicit downgrade)"
            );
        }
    }

    #[test]
    fn store_version_parse_unknown_falls_back_to_v2() {
        // Typos and stray values fall through to the default (v2),
        // not v1 — pre-Phase-4d the fallback was v1 because v2 was
        // dev-only opt-in. Post-flip the safe default is v2.
        for s in ["v3", "v2x", "true", "yes", "on", "junk"] {
            assert_eq!(
                StoreVersion::parse(Some(s)),
                StoreVersion::V2,
                "input {s:?} should fall back to v2"
            );
        }
    }

    #[test]
    fn store_version_is_v2_predicate() {
        assert!(StoreVersion::V2.is_v2());
        assert!(!StoreVersion::V1.is_v2());
    }

    #[test]
    fn store_version_display_round_trips_through_parse() {
        for v in [StoreVersion::V1, StoreVersion::V2] {
            let rendered = format!("{v}");
            assert_eq!(StoreVersion::parse(Some(&rendered)), v);
        }
    }

    // ── F2 — V2BaselineIndex contracts ─────────────────────────────────

    use crate::v2::{LinkEntryRequest, LinkMetaPlatform, Store as V2Store};

    fn f2_sample_meta_platform() -> LinkMetaPlatform {
        LinkMetaPlatform {
            os: "darwin".into(),
            cpu: "arm64".into(),
            libc: None,
        }
    }

    fn f2_synthetic_sri(seed: &[u8]) -> String {
        crate::compute_sri_hash(seed)
    }

    fn f2_write_object(store: &V2Store, sri: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let dir = store.paths().object_dir(sri).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in files {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        std::fs::write(dir.join(".integrity"), sri).unwrap();
        dir
    }

    fn f2_sample_key(name: &str, version: &str) -> crate::v2::GraphKey {
        use crate::v2::{GraphKeyInputs, LinkerModeTag, PlatformTuple};
        let inputs = GraphKeyInputs::new(
            name,
            version,
            PlatformTuple::new("darwin", "arm64", None),
            LinkerModeTag::Isolated,
        );
        crate::v2::GraphKey::derive(&inputs)
    }

    /// Construction against an empty `~/.lpm/` directory yields an
    /// empty index. Lookup against any coords returns `None` so the
    /// index-aware helper falls through to v1 cleanly. This is the
    /// "no v2 store at all" case (pure-v1 test fixtures, fresh
    /// install pre-4b populated v1 only).
    #[test]
    fn f2_v2_baseline_index_empty_when_no_v2_links() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        assert!(index.lookup("nonexistent", "1.0.0").is_none());
    }

    /// A populated v2 store yields a hit through the indexed lookup.
    /// This is the hot path for `lpm rebuild` on a v2-default install.
    #[test]
    fn f2_v2_baseline_index_hits_populated_link_entry() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let store = V2Store::from_lpm_root(&lpm_root);

        let sri = f2_synthetic_sri(b"f2_index/lodash");
        f2_write_object(
            &store,
            &sri,
            &[(
                "package.json",
                b"{\"name\":\"lodash\",\"version\":\"4.17.21\"}",
            )],
        );
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: std::sync::Arc::new(f2_sample_key("lodash", "4.17.21")),
                source_sri: sri.clone(),
                object_dir: store.paths().object_dir(&sri).unwrap(),
                deps: vec![],
                platform: std::sync::Arc::new(f2_sample_meta_platform()),
            })
            .unwrap();

        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        let hit = index
            .lookup("lodash", "4.17.21")
            .expect("populated link entry must be indexed");
        assert_eq!(hit.layout, PackageBaselineLayout::V2);
        assert_eq!(hit.integrity, sri);
        assert!(
            hit.package_dir.exists(),
            "indexed package_dir must point at a real materialization"
        );
        assert!(
            hit.pristine_dir.exists(),
            "indexed pristine_dir must point at the populated objects/<sri>/"
        );
        // Different by design under v2 — pristine_dir is the immutable
        // object dir; package_dir is the link entry's clonefile copy.
        assert_ne!(
            hit.package_dir, hit.pristine_dir,
            "v2 entries must surface a distinct pristine_dir"
        );
    }

    /// `find_installed_package_baseline_indexed` falls through to v1
    /// when the index has no entry. Mirror of the legacy helper's
    /// fall-through path, but reachable via the per-loop O(1) form.
    #[test]
    fn f2_indexed_helper_falls_through_to_v1_on_index_miss() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        // Seed v1 only (no v2 link entries) — index is empty, but the
        // legacy v1 fallback should still resolve the package.
        let store_v1 = PackageStore::from_root(&lpm_root);
        let pkg_dir = store_v1.package_dir("legacy", "1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join(".integrity"), "sha512-stub").unwrap();
        std::fs::write(pkg_dir.join("package.json"), r#"{"name":"legacy"}"#).unwrap();

        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        let resolved =
            find_installed_package_baseline_indexed(&index, &lpm_root, "legacy", "1.0.0")
                .expect("v1 fallback must populate the result");
        assert_eq!(resolved.layout, PackageBaselineLayout::V1);
        assert_eq!(
            resolved.package_dir, resolved.pristine_dir,
            "v1 entries alias pristine_dir to package_dir (the v1 store \
             dir is never mutated by patches)"
        );
    }

    /// **Phase 66 confidence-followup F1+F2 review (2026-05-09)** —
    /// when two link entries legitimately share the same
    /// `(name, version)` (the post-F1 default for the patched-vs-
    /// unpatched cross-project case, and the multi-source-same-coords
    /// case), `V2BaselineIndex::for_project` MUST resolve to the
    /// link entry the CURRENT project's tree points at — not the
    /// first match in global directory order.
    ///
    /// The test seeds two link entries for `lodash@1.0.0`, points
    /// project A's `node_modules/lodash` symlink at the SECOND one,
    /// and asserts the project-scoped index returns that one. The
    /// global `V2BaselineIndex::build` would (under the unfixed
    /// code) return whichever entry came first in directory order
    /// — wrong half the time for project A.
    ///
    /// Without this fix `lpm rebuild` running in project A could
    /// read scripts / trust state from the WRONG link entry and
    /// stamp the build marker into a sibling project's store dir.
    #[test]
    fn f1f2_for_project_resolves_to_the_link_entry_this_project_uses() {
        use crate::v2::link_meta::{LinkMeta, LinkMetaPlatform};
        use chrono::Utc;

        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        // Seed two link entries for the same coords. Both have
        // realistic (different) graph-key dir names; both have a
        // populated package dir + sidecar. The two coexist legitimately
        // post-F1 (e.g. one carries `patch_fingerprint`, the other
        // doesn't).
        let v2_links_root = dir.path().join("store").join("v2").join("links");
        let entry_unpatched = v2_links_root.join("lodash@1.0.0+aaaaaaaaaaaaaaaa");
        let entry_patched = v2_links_root.join("lodash@1.0.0+bbbbbbbbbbbbbbbb");
        for (link_dir, suffix) in [
            (&entry_unpatched, "aaaaaaaaaaaaaaaa"),
            (&entry_patched, "bbbbbbbbbbbbbbbb"),
        ] {
            let pkg_dir = link_dir.join("node_modules").join("lodash");
            std::fs::create_dir_all(&pkg_dir).unwrap();
            std::fs::write(
                pkg_dir.join("package.json"),
                r#"{"name":"lodash","version":"1.0.0"}"#,
            )
            .unwrap();
            let meta = LinkMeta {
                schema: 1,
                graph_key: format!("lodash@1.0.0+{suffix}"),
                graph_key_digest_hex: format!("{suffix}{suffix}{suffix}{suffix}"),
                name: "lodash".into(),
                version: "1.0.0".into(),
                source_sri: format!("sha512-stub-{suffix}"),
                object_path: format!("objects/sha512-stub-{suffix}"),
                deps: vec![],
                platform: std::sync::Arc::new(LinkMetaPlatform {
                    os: "darwin".into(),
                    cpu: "arm64".into(),
                    libc: None,
                }),
                created_at: Utc::now(),
                last_referenced_at: Utc::now(),
            };
            meta.write_to(link_dir).unwrap();
        }

        // Build project A: its `node_modules/lodash` symlinks INTO
        // the patched entry. This is the load-bearing fixture: the
        // project-scoped lookup must follow this symlink and return
        // the patched entry, never the unpatched one.
        let project = dir.path().join("project-a");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            entry_patched.join("node_modules").join("lodash"),
            project.join("node_modules").join("lodash"),
        )
        .unwrap();

        // Sanity: the global index could return either entry — that's
        // exactly the ambiguity the project-scoped lookup is meant to
        // eliminate.
        let global = V2BaselineIndex::build(&lpm_root).unwrap();
        let global_hit = global.lookup("lodash", "1.0.0").unwrap();
        let global_resolves_correctly = global_hit
            .package_dir
            .starts_with(entry_patched.join("node_modules"));
        // We don't assert which one global returns — just that the
        // project-scoped variant below is unambiguous about the right
        // answer.
        let _ = global_resolves_correctly;

        // The project-scoped index MUST land on the patched entry
        // because that's where project A's symlink resolves to. This
        // is the F1+F2 review's load-bearing assertion.
        let project_index = V2BaselineIndex::for_project(&project, &lpm_root).unwrap();
        let project_hit = project_index
            .lookup("lodash", "1.0.0")
            .expect("project-scoped index must resolve the package");
        assert!(
            project_hit
                .package_dir
                .starts_with(entry_patched.join("node_modules")),
            "project-scoped lookup MUST return the link entry the project's \
             symlinks resolve to (patched entry), not the first global match. \
             Got: {:?}, expected under: {:?}",
            project_hit.package_dir,
            entry_patched
        );
    }

    /// `for_project` reaches transitive dependencies via the BFS over
    /// `LinkMeta.deps`. The seed is the project's direct symlink; the
    /// transitive's link entry is reconstructed from the seed
    /// sidecar's `target_graph_key` digest (16-hex prefix) + name +
    /// version.
    ///
    /// Without this, `live_package_dir_with_v2`'s transitive fallback
    /// (which today routes through `Store::find_link_package_dir`'s
    /// global first-match) would still be ambiguous post-F1.
    #[test]
    fn f1f2_for_project_reaches_transitive_via_link_meta_deps() {
        use crate::v2::link_meta::{LinkMeta, LinkMetaDep, LinkMetaPlatform};
        use chrono::Utc;

        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        let v2_links_root = dir.path().join("store").join("v2").join("links");

        // Transitive: `tslib@2.0.0` lives in its own link entry, never
        // symlinked at the project root.
        let tslib_short = "1111111111111111";
        let tslib_full = format!("{tslib_short}{tslib_short}{tslib_short}{tslib_short}");
        let tslib_entry = v2_links_root.join(format!("tslib@2.0.0+{tslib_short}"));
        let tslib_pkg = tslib_entry.join("node_modules").join("tslib");
        std::fs::create_dir_all(&tslib_pkg).unwrap();
        std::fs::write(
            tslib_pkg.join("package.json"),
            r#"{"name":"tslib","version":"2.0.0"}"#,
        )
        .unwrap();
        let tslib_meta = LinkMeta {
            schema: 1,
            graph_key: format!("tslib@2.0.0+{tslib_short}"),
            graph_key_digest_hex: tslib_full.clone(),
            name: "tslib".into(),
            version: "2.0.0".into(),
            source_sri: "sha512-stub-tslib".into(),
            object_path: "objects/sha512-stub-tslib".into(),
            deps: vec![],
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        };
        tslib_meta.write_to(&tslib_entry).unwrap();

        // Direct: `consumer@1.0.0` is a project root dep that depends
        // on tslib. Its `LinkMeta.deps` carries tslib's full digest.
        let consumer_short = "2222222222222222";
        let consumer_entry = v2_links_root.join(format!("consumer@1.0.0+{consumer_short}"));
        let consumer_pkg = consumer_entry.join("node_modules").join("consumer");
        std::fs::create_dir_all(&consumer_pkg).unwrap();
        std::fs::write(
            consumer_pkg.join("package.json"),
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"tslib":"2.0.0"}}"#,
        )
        .unwrap();
        let consumer_meta = LinkMeta {
            schema: 1,
            graph_key: format!("consumer@1.0.0+{consumer_short}"),
            graph_key_digest_hex: format!(
                "{consumer_short}{consumer_short}{consumer_short}{consumer_short}"
            ),
            name: "consumer".into(),
            version: "1.0.0".into(),
            source_sri: "sha512-stub-consumer".into(),
            object_path: "objects/sha512-stub-consumer".into(),
            deps: vec![LinkMetaDep {
                local: "tslib".into(),
                target_graph_key: tslib_full.clone(),
                target_name: "tslib".into(),
                target_version: "2.0.0".into(),
            }],
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        };
        consumer_meta.write_to(&consumer_entry).unwrap();

        // Project: only the consumer is symlinked at the root; tslib
        // is reachable ONLY via `consumer`'s sidecar deps.
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            consumer_entry.join("node_modules").join("consumer"),
            project.join("node_modules").join("consumer"),
        )
        .unwrap();

        let index = V2BaselineIndex::for_project(&project, &lpm_root).unwrap();
        let consumer_hit = index.lookup("consumer", "1.0.0").unwrap();
        assert!(
            consumer_hit
                .package_dir
                .starts_with(consumer_entry.join("node_modules"))
        );
        let tslib_hit = index
            .lookup("tslib", "2.0.0")
            .expect("BFS through LinkMeta.deps must reach the transitive");
        assert!(
            tslib_hit
                .package_dir
                .starts_with(tslib_entry.join("node_modules")),
            "transitive lookup MUST land on tslib's link entry, not anywhere \
             else (got: {:?}, expected under {:?})",
            tslib_hit.package_dir,
            tslib_entry,
        );
    }

    /// Scoped direct deps live under `node_modules/@scope/pkg`, so the
    /// project root contains a real `@scope/` directory and the actual
    /// package symlink is nested one level deeper. `for_project` must
    /// seed from that nested symlink too, otherwise rebuild / install-
    /// hint silently skip the entire scoped direct-dependency surface.
    #[test]
    fn f1f2_for_project_includes_scoped_direct_dependencies() {
        use crate::v2::link_meta::{LinkMeta, LinkMetaPlatform};
        use chrono::Utc;

        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());

        let v2_links_root = dir.path().join("store").join("v2").join("links");
        let entry = v2_links_root.join("@scope+pkg@1.0.0+cccccccccccccccc");
        let pkg_dir = entry.join("node_modules").join("@scope/pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"@scope/pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        let meta = LinkMeta {
            schema: 1,
            graph_key: "@scope+pkg@1.0.0+cccccccccccccccc".into(),
            graph_key_digest_hex:
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            name: "@scope/pkg".into(),
            version: "1.0.0".into(),
            source_sri: "sha512-stub-scoped".into(),
            object_path: "objects/sha512-stub-scoped".into(),
            deps: vec![],
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
            created_at: Utc::now(),
            last_referenced_at: Utc::now(),
        };
        meta.write_to(&entry).unwrap();

        let project = dir.path().join("project");
        let project_scope_dir = project.join("node_modules").join("@scope");
        std::fs::create_dir_all(&project_scope_dir).unwrap();
        std::os::unix::fs::symlink(
            entry.join("node_modules").join("@scope/pkg"),
            project_scope_dir.join("pkg"),
        )
        .unwrap();

        let index = V2BaselineIndex::for_project(&project, &lpm_root).unwrap();
        let hit = index
            .lookup("@scope/pkg", "1.0.0")
            .expect("scoped direct dependency must seed the project-scoped index");
        assert!(
            hit.package_dir.starts_with(entry.join("node_modules")),
            "scoped direct dep must resolve to its link entry; got {:?}",
            hit.package_dir
        );
    }

    /// Multi-coords collision: when two link entries share the same
    /// `(name, version)` (multi-source-same-coords or peer-divergent),
    /// the index keeps the FIRST entry seen — exactly matching the
    /// legacy linear scan's tie-breaking. Without this, a re-index
    /// could expose a different first-match across runs.
    #[test]
    fn f2_v2_baseline_index_first_match_wins_for_duplicate_coords() {
        // The legacy `find_installed_package_baseline` scanned in
        // `iter_link_entries()` directory order and returned the
        // first match. The index must preserve that contract — a
        // duplicate insert must NOT overwrite the first hit.
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = lpm_common::LpmRoot::from_dir(dir.path());
        let store = V2Store::from_lpm_root(&lpm_root);

        // Two link entries for the same `(react, 18.0.0)` under
        // distinct graph keys (peer-divergent inputs differ in
        // `with_root_link_names` to fork the digest).
        use crate::v2::{GraphKeyInputs, LinkerModeTag, PlatformTuple};
        let key_a = crate::v2::GraphKey::derive(
            &GraphKeyInputs::new(
                "react",
                "18.0.0",
                PlatformTuple::new("darwin", "arm64", None),
                LinkerModeTag::Isolated,
            )
            .with_root_link_names(Some(vec!["react".into()])),
        );
        let key_b = crate::v2::GraphKey::derive(
            &GraphKeyInputs::new(
                "react",
                "18.0.0",
                PlatformTuple::new("darwin", "arm64", None),
                LinkerModeTag::Isolated,
            )
            .with_root_link_names(Some(vec!["react".into(), "alias".into()])),
        );
        assert_ne!(key_a, key_b, "fixture must produce divergent keys");

        let sri = f2_synthetic_sri(b"f2_index/react");
        f2_write_object(
            &store,
            &sri,
            &[(
                "package.json",
                b"{\"name\":\"react\",\"version\":\"18.0.0\"}",
            )],
        );
        for key in [std::sync::Arc::new(key_a), std::sync::Arc::new(key_b)] {
            store
                .populate_link_entry(LinkEntryRequest {
                    graph_key: key,
                    source_sri: sri.clone(),
                    object_dir: store.paths().object_dir(&sri).unwrap(),
                    deps: vec![],
                    platform: std::sync::Arc::new(f2_sample_meta_platform()),
                })
                .unwrap();
        }

        let index = V2BaselineIndex::build(&lpm_root).unwrap();
        let hit = index
            .lookup("react", "18.0.0")
            .expect("either entry should satisfy the lookup");
        // Re-build and confirm the same entry wins. Stable
        // first-match-wins in the face of multi-entry coords.
        let index2 = V2BaselineIndex::build(&lpm_root).unwrap();
        let hit2 = index2.lookup("react", "18.0.0").unwrap();
        assert_eq!(
            hit.package_dir, hit2.package_dir,
            "rebuilding the index against the same disk state must \
             preserve first-match identity"
        );
    }
}
