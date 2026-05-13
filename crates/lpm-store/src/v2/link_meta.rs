//! Sidecar metadata that ships with every v2 link entry.
//!
//! The metadata file at `links/<graph-key>/.lpm-link-meta.json` makes
//! `lpm cache prune` traversable: given just the link directory, prune
//! can identify the source object + sibling targets without
//! filesystem-walking back through the clonefile/hardlink relationship
//! (which on APFS / Linux ext4 / hardlink-fallback paths gives no
//! traversable reference back to the source).
//!
//! Mandatory in v1 scope per Phase 66 preplan §2.4 — required for:
//! - **Object orphan detection** (clonefile/hardlink doesn't preserve a
//!   reverse pointer; `source_sri` carries it explicitly).
//! - **Link orphan detection** via BFS over `deps[].target_graph_key`.
//! - **Migration recovery**: a partially-populated link entry that
//!   crashed before metadata-write is detected by absent sidecar.
//! - **`--max-age` prune**: `last_referenced_at` updated on each install
//!   that resolves to this graph-key.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use lpm_common::LpmError;
use serde::{Deserialize, Serialize};

use crate::v2::graph_key::GraphKey;

/// Sidecar file name. Lives at the root of every
/// `links/<graph-key>/` directory (not inside `node_modules/`).
pub const LINK_META_FILENAME: &str = ".lpm-link-meta.json";

/// Schema version of the sidecar payload. Bump in lock-step with any
/// breaking field change. Readers MUST reject unknown versions and
/// treat the link entry as malformed (i.e., re-materialize on next
/// install, prune-eligible in the meantime).
pub const LINK_META_SCHEMA_VERSION: u32 = 1;

/// One sibling-symlink target recorded in [`LinkMeta::deps`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkMetaDep {
    /// Local name as it appears under
    /// `links/<graph-key>/node_modules/<local>/`. Matches the
    /// consumer's `package.json > dependencies` key (different from
    /// the canonical name only for npm aliases).
    pub local: String,
    /// Full BLAKE3 digest of the target's [`GraphKey`], lowercase hex.
    pub target_graph_key: String,
    /// Canonical name of the target package. Recorded so
    /// `lpm cache prune` can present human-readable diagnostics
    /// without round-tripping through the target's own sidecar.
    pub target_name: String,
    /// Exact resolved target version. Same rationale as
    /// `target_name` — keeps prune output readable.
    pub target_version: String,
}

/// Platform tuple as serialized inside [`LinkMeta`].
///
/// Stored separately from [`crate::v2::PlatformTuple`] so the on-disk
/// schema can evolve independently of the in-memory representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkMetaPlatform {
    pub os: String,
    pub cpu: String,
    /// `Some` only on Linux. Serialized as `null` elsewhere; round-trips
    /// faithfully.
    pub libc: Option<String>,
}

/// Complete sidecar payload for one link entry.
///
/// Preplan §2.4 schema v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkMeta {
    /// Schema version. Always [`LINK_META_SCHEMA_VERSION`] for files
    /// this build of lpm writes; readers reject unknown values.
    pub schema: u32,
    /// Self-reference: the directory-name form of this entry's
    /// [`GraphKey`] (`<safe>@<ver>+<short_hex>`). Repeated here so
    /// prune doesn't need to parse the parent dir name to learn it.
    pub graph_key: String,
    /// Full 64-hex-char BLAKE3 digest of the [`GraphKey`]. Used by
    /// prune's reverse mapping (link → object) — see
    /// [`Self::source_sri`] / [`Self::object_path`].
    pub graph_key_digest_hex: String,
    /// Canonical registry name of the package this link materializes.
    pub name: String,
    /// Exact resolved version of that package.
    pub version: String,
    /// SRI integrity string of the source tarball. Same value persisted
    /// in v1's `.integrity` file. Carries the reverse pointer to the
    /// content-addressable object.
    pub source_sri: String,
    /// Relative path from the v2 store root to the object directory
    /// (e.g. `objects/sha512-deadbeef.../`). Stored relative so the
    /// store is portable across `$LPM_HOME` overrides; absolute paths
    /// would lock the user to one cache location.
    pub object_path: String,
    /// Sibling-dep symlink targets — the BFS edges prune walks.
    pub deps: Vec<LinkMetaDep>,
    /// Platform tuple frozen at materialization time. Lets prune detect
    /// "wrong-architecture leftovers" if a user's host changed (e.g.,
    /// re-imaged from arm64 → x64 with a shared `$HOME`).
    pub platform: Arc<LinkMetaPlatform>,
    /// First-write timestamp.
    pub created_at: DateTime<Utc>,
    /// Updated on every install that resolves to this graph-key.
    /// Drives `lpm cache prune --max-age <duration>` semantics.
    pub last_referenced_at: DateTime<Utc>,
}

impl LinkMeta {
    /// Construct a sidecar from the inputs known at populate time.
    ///
    /// Both timestamps default to the current UTC time; bump
    /// `last_referenced_at` separately on subsequent installs via
    /// [`Self::touch`].
    pub fn new(
        graph_key: &GraphKey,
        source_sri: impl Into<String>,
        object_path: impl Into<String>,
        deps: Vec<LinkMetaDep>,
        platform: Arc<LinkMetaPlatform>,
    ) -> Self {
        let now = Utc::now();
        Self {
            schema: LINK_META_SCHEMA_VERSION,
            graph_key: graph_key.dir_name().to_owned(),
            graph_key_digest_hex: graph_key.digest_hex(),
            name: graph_key.name().to_string(),
            version: graph_key.version().to_string(),
            source_sri: source_sri.into(),
            object_path: object_path.into(),
            deps,
            platform,
            created_at: now,
            last_referenced_at: now,
        }
    }

    /// Update [`Self::last_referenced_at`] to the current UTC time.
    /// Called on every install that re-resolves to this graph-key so
    /// `lpm cache prune --max-age` distinguishes warm graph-keys from
    /// abandoned ones.
    pub fn touch(&mut self) {
        self.last_referenced_at = Utc::now();
    }

    /// Phase 66 followup #3 — refresh the sidecar's "last touched"
    /// signal via a single [`std::fs::File::set_modified`] call (one
    /// `utimes(2)` syscall) instead of read+modify+write+rename (three
    /// syscalls plus serde JSON round-trip).
    ///
    /// The on-disk JSON's `last_referenced_at` field becomes a stale
    /// snapshot from the initial population; prune reconciles it
    /// against the file mtime via
    /// [`Self::effective_last_referenced_at`]. Schema-compatible —
    /// older sidecars predating this change still parse cleanly and
    /// their `last_referenced_at` remains valid (just always ≤ mtime).
    ///
    /// Idempotent. Errors from the underlying `set_modified` are
    /// returned as `LpmError::Store`; callers may safely treat the
    /// failure as non-fatal (a missed touch only widens prune's
    /// view of cold entries by one install cycle).
    pub fn touch_on_disk(sidecar_path: &Path) -> Result<(), LpmError> {
        let file = std::fs::File::options()
            .write(true)
            .open(sidecar_path)
            .map_err(|e| {
                LpmError::Store(format!(
                    "failed to open v2 link sidecar for touch at {}: {e}",
                    sidecar_path.display()
                ))
            })?;
        file.set_modified(std::time::SystemTime::now())
            .map_err(|e| {
                LpmError::Store(format!(
                    "failed to update v2 link sidecar mtime at {}: {e}",
                    sidecar_path.display()
                ))
            })?;
        Ok(())
    }

    /// Phase 66 followup #3 — the touch-time prune actually consults.
    ///
    /// Returns `max(self.last_referenced_at, file_mtime(sidecar_path))`.
    /// Under [`Self::touch_on_disk`] semantics, file mtime is the
    /// authoritative "last referenced" signal post-population; the
    /// JSON field is preserved only for backward-compat with
    /// pre-followup-#3 sidecars (where `touch` rewrote the field).
    /// Falling back to the JSON field when mtime is unreadable means
    /// the prune contract degrades gracefully on permission/EIO
    /// failures rather than over-aggressively expiring entries.
    pub fn effective_last_referenced_at(&self, sidecar_path: &Path) -> DateTime<Utc> {
        match std::fs::metadata(sidecar_path).and_then(|m| m.modified()) {
            Ok(mtime) => {
                let mtime_utc: DateTime<Utc> = mtime.into();
                if mtime_utc > self.last_referenced_at {
                    mtime_utc
                } else {
                    self.last_referenced_at
                }
            }
            Err(_) => self.last_referenced_at,
        }
    }

    /// Read a sidecar from `<link_dir>/.lpm-link-meta.json`.
    ///
    /// Returns [`LpmError::Store`] on missing-file / malformed JSON /
    /// unknown-schema. The unknown-schema path is the load-bearing
    /// safety: a future lpm reading a sidecar from an even-newer build
    /// must NOT trust unknown fields.
    pub fn read_from(link_dir: &Path) -> Result<Self, LpmError> {
        let path = link_dir.join(LINK_META_FILENAME);
        let bytes = std::fs::read(&path).map_err(|e| {
            LpmError::Store(format!(
                "failed to read v2 link sidecar at {}: {e}",
                path.display()
            ))
        })?;
        let parsed: LinkMeta = serde_json::from_slice(&bytes).map_err(|e| {
            LpmError::Store(format!(
                "malformed v2 link sidecar at {}: {e}",
                path.display()
            ))
        })?;
        if parsed.schema != LINK_META_SCHEMA_VERSION {
            return Err(LpmError::Store(format!(
                "v2 link sidecar at {} has unsupported schema {} (expected {})",
                path.display(),
                parsed.schema,
                LINK_META_SCHEMA_VERSION
            )));
        }
        Ok(parsed)
    }

    /// Serialize and atomically write to `<link_dir>/.lpm-link-meta.json`.
    ///
    /// The write is staged at `<link_dir>/.lpm-link-meta.json.tmp.<pid>`
    /// then renamed into place — concurrent installs pointing at the
    /// same graph-key see either the old payload or the new payload,
    /// never a half-written one.
    ///
    /// Use [`Self::write_to_unpublished`] when the caller already holds an
    /// unpublished staging directory (e.g. cold population): the outer
    /// atomic-rename of the staging dir provides the visibility boundary,
    /// so the inner tmp+rename is pure overhead.
    pub fn write_to(&self, link_dir: &Path) -> Result<PathBuf, LpmError> {
        let final_path = link_dir.join(LINK_META_FILENAME);
        let tmp_path = link_dir.join(format!("{LINK_META_FILENAME}.tmp.{}", std::process::id()));

        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| LpmError::Store(format!("failed to serialize v2 link sidecar: {e}")))?;

        // Best-effort cleanup of stale tmp-file from a previous crash.
        if tmp_path.exists() {
            let _ = std::fs::remove_file(&tmp_path);
        }

        std::fs::write(&tmp_path, &bytes).map_err(|e| {
            LpmError::Store(format!(
                "failed to stage v2 link sidecar at {}: {e}",
                tmp_path.display()
            ))
        })?;

        std::fs::rename(&tmp_path, &final_path).map_err(|e| {
            // Best-effort tmp cleanup if the rename failed.
            let _ = std::fs::remove_file(&tmp_path);
            LpmError::Store(format!(
                "failed to atomically install v2 link sidecar at {}: {e}",
                final_path.display()
            ))
        })?;

        Ok(final_path)
    }

    /// Write the sidecar directly into a directory that is NOT yet
    /// observable to other processes. Skips the inner tmp+rename used by
    /// [`Self::write_to`].
    ///
    /// Atomicity invariant: the caller MUST be writing into a staging dir
    /// that will be published via a single atomic rename later (e.g.
    /// `populate_link_entry`'s `links/<key>.tmp.<pid>.<tid>/` →
    /// `links/<key>/`). Under that contract, no observer can ever see the
    /// half-written sidecar — the outer rename is the visibility
    /// boundary, so the inner tmp+rename is dead syscalls.
    ///
    /// Wins ~35 % of cold-install rename syscalls (one per link entry ×
    /// hundreds of packages) per Phase 66 post-flamegraph audit
    /// (2026-05-09).
    pub fn write_to_unpublished(&self, staging_dir: &Path) -> Result<PathBuf, LpmError> {
        let final_path = staging_dir.join(LINK_META_FILENAME);
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| LpmError::Store(format!("failed to serialize v2 link sidecar: {e}")))?;
        std::fs::write(&final_path, &bytes).map_err(|e| {
            LpmError::Store(format!(
                "failed to write v2 link sidecar at {}: {e}",
                final_path.display()
            ))
        })?;
        Ok(final_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::graph_key::{GraphKeyInputs, LinkerModeTag};
    use crate::v2::platform::PlatformTuple;

    fn sample_graph_key() -> GraphKey {
        let inputs = GraphKeyInputs::new(
            "express",
            "4.21.0",
            PlatformTuple::new("darwin", "arm64", None),
            LinkerModeTag::Isolated,
        );
        GraphKey::derive(&inputs)
    }

    fn sample_meta() -> LinkMeta {
        let key = sample_graph_key();
        LinkMeta::new(
            &key,
            "sha512-deadbeef",
            "objects/sha512-deadbeef",
            vec![LinkMetaDep {
                local: "debug".into(),
                target_graph_key: "0".repeat(64),
                target_name: "debug".into(),
                target_version: "4.3.4".into(),
            }],
            Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
        )
    }

    #[test]
    fn round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let meta = sample_meta();
        let written = meta.write_to(dir.path()).unwrap();
        assert!(written.ends_with(LINK_META_FILENAME));
        let read_back = LinkMeta::read_from(dir.path()).unwrap();
        assert_eq!(meta, read_back);
    }

    #[test]
    fn write_is_atomic_no_tmp_lingers() {
        let dir = tempfile::tempdir().unwrap();
        let meta = sample_meta();
        meta.write_to(dir.path()).unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        // Only the final sidecar should remain.
        assert_eq!(entries, vec![LINK_META_FILENAME.to_string()]);
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = sample_meta();
        meta.schema = 99;
        let final_path = dir.path().join(LINK_META_FILENAME);
        std::fs::write(&final_path, serde_json::to_vec(&meta).unwrap()).unwrap();
        let err = LinkMeta::read_from(dir.path()).unwrap_err();
        assert!(format!("{err}").contains("unsupported schema 99"));
    }

    #[test]
    fn malformed_json_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LINK_META_FILENAME), b"{not json").unwrap();
        let err = LinkMeta::read_from(dir.path()).unwrap_err();
        assert!(format!("{err}").contains("malformed v2 link sidecar"));
    }

    #[test]
    fn missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = LinkMeta::read_from(dir.path()).unwrap_err();
        assert!(format!("{err}").contains("failed to read v2 link sidecar"));
    }

    #[test]
    fn touch_advances_last_referenced_at() {
        let mut meta = sample_meta();
        let before = meta.last_referenced_at;
        // Touch is monotonic non-decreasing on UTC; on fast machines
        // the chrono::Utc::now() resolution is sub-microsecond so the
        // bump should happen on the same call.
        std::thread::sleep(std::time::Duration::from_millis(2));
        meta.touch();
        assert!(meta.last_referenced_at > before);
    }

    #[test]
    fn touch_on_disk_advances_file_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let meta = sample_meta();
        let path = meta.write_to(dir.path()).unwrap();
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        // FAT/CIFS-tolerant sleep so the mtime delta is observable on
        // every supported test runner.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        LinkMeta::touch_on_disk(&path).unwrap();
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert!(mtime_after > mtime_before);
    }

    #[test]
    fn effective_last_referenced_at_takes_max_of_json_and_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let meta = sample_meta();
        let path = meta.write_to(dir.path()).unwrap();
        // The JSON field and the mtime are both ~now after `write_to`
        // — the effective value is dominated by whichever is higher.
        let original_json_field = meta.last_referenced_at;
        let effective = meta.effective_last_referenced_at(&path);
        assert!(
            effective >= original_json_field,
            "effective is at least the JSON field"
        );

        // After a touch, mtime advances past the (frozen) JSON field —
        // effective tracks mtime, NOT the JSON field.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        LinkMeta::touch_on_disk(&path).unwrap();
        let after_touch = meta.effective_last_referenced_at(&path);
        assert!(after_touch > original_json_field);
    }

    #[test]
    fn graph_key_digest_hex_round_trips() {
        let key = sample_graph_key();
        let meta = LinkMeta::new(
            &key,
            "sha512-x",
            "objects/sha512-x",
            vec![],
            Arc::new(LinkMetaPlatform {
                os: "darwin".into(),
                cpu: "arm64".into(),
                libc: None,
            }),
        );
        // The recorded digest hex must match the GraphKey's own.
        assert_eq!(meta.graph_key_digest_hex, key.digest_hex());
        // And feeding it back through GraphKey::from_recorded yields
        // the same key.
        let mut digest_bytes = [0u8; 32];
        let raw = hex::decode(&meta.graph_key_digest_hex).unwrap();
        digest_bytes.copy_from_slice(&raw);
        let reconstructed = GraphKey::from_recorded(&meta.name, &meta.version, digest_bytes);
        assert_eq!(reconstructed, key);
    }
}
