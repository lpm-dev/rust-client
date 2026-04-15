//! Phase 37 — write-ahead log for global-install transactions.
//!
//! The WAL records every state transition the install pipeline performs
//! against `~/.lpm/global/` so a `kill -9` mid-install can recover
//! deterministically on the next `lpm` invocation. M2 ships the
//! framing/storage layer; M3 wires it into the actual transaction flow
//! (see plan §"Crash-safe transactions").
//!
//! ## Why framed records, not plain JSONL
//!
//! A torn append (process killed mid-write) on a plain JSONL file is
//! ambiguous — the last line may parse as truncated JSON, or as garbage
//! that breaks the parser entirely. Length + CRC + sentinel framing
//! makes torn-tail detection deterministic: any record whose length
//! prefix doesn't fit, whose CRC doesn't match, or whose sentinel byte
//! is missing is treated as a torn write and the file is truncated to
//! the last good offset.
//!
//! ## Record format (on-disk, big-endian)
//!
//! ```text
//!   ┌───────────────┬───────────────┬───────────────┬─────────┐
//!   │ payload_len   │ CRC32         │ payload bytes │ 0x0A    │
//!   │ (u32 BE, 4)   │ (u32 BE, 4)   │ (payload_len) │ (1)     │
//!   └───────────────┴───────────────┴───────────────┴─────────┘
//! ```
//!
//! - `payload_len` does NOT include the header (8 bytes) or sentinel (1 byte).
//! - `CRC32` is the IEEE polynomial (crc32fast::Hasher), computed over
//!   `payload` only.
//! - The trailing `0x0A` is a redundant sanity byte. It is **not** a
//!   record separator; it is a sentinel checked during recovery so a
//!   subtle off-by-one in the length field shows up as a framing error
//!   rather than silently misaligning the next record.
//! - `payload` is UTF-8 JSON. The structure of the JSON is the
//!   `WalRecord` type below; readers tolerant of unknown variants are
//!   the responsibility of the M3 reconciliation logic.
//!
//! ## Recovery semantics
//!
//! [`WalReader::scan`] walks records from the start of the file. Any
//! record that fails framing validation truncates the read at that
//! offset and returns `(records_so_far, last_good_offset)`. The caller
//! can then `set_len(last_good_offset)` under the global tx-lock to
//! discard the torn tail. Recovery is idempotent — running `scan` twice
//! returns the same set of records.

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Sentinel byte appended after every payload. Catches off-by-one errors
/// in length-field reads that would otherwise silently misalign reads of
/// the next record.
pub const RECORD_SENTINEL: u8 = 0x0A;

/// Minimum bytes needed to even begin parsing a record: 4 (len) + 4
/// (crc) + 0 (empty payload allowed) + 1 (sentinel).
pub const MIN_RECORD_BYTES: usize = 4 + 4 + 1;

#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("payload too large for u32 length prefix: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
}

impl From<WalError> for LpmError {
    fn from(e: WalError) -> Self {
        match e {
            WalError::Io(e) => LpmError::Io(e),
            other => LpmError::Io(std::io::Error::other(other.to_string())),
        }
    }
}

/// Discriminated union of every write the global install transaction
/// emits. The `op` field is the discriminator; payload schema lives
/// alongside each variant.
///
/// **Forward-compat policy.** Adding a new variant in a newer `lpm`
/// release is allowed — but an older binary that encounters the new
/// variant in a recovery scan must not silently skip past it. Doing so
/// would leave the older binary unable to reason about whether the
/// containing transaction committed or aborted, and could lead to
/// incorrect roll-forward / roll-back decisions. The scanner reports
/// unknown variants via [`ScanStop::UnknownOp`] and returns the records
/// it has so far; recovery treats this as "WAL was written by a newer
/// lpm — upgrade required" and refuses to mutate state.
/// Heavy payload for the `Intent` variant. Boxed inside [`WalRecord`] so
/// the `Commit` / `Abort` variants don't pay for the `Intent`-only
/// fields when sitting in a `Vec<WalRecord>` during recovery scans.
///
/// Roll-forward / roll-back recovery requires this payload to carry
/// the **complete** description of the manifest mutation so the
/// reconciliation logic can reconstruct the post-commit state without
/// inspecting any other source. That includes `[aliases]` entries the
/// transaction will write — those live in their own table per the
/// manifest schema and are not redundant with `commands` on the
/// package row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentPayload {
    /// Stable transaction id. UUIDs are heavy for the use case;
    /// `<unix_nanos>-<pid>` is a perfectly adequate uniqueness
    /// guarantee within a single host.
    pub tx_id: String,
    pub kind: TxKind,
    pub package: String,
    /// Absolute path of the new install root being prepared.
    pub new_root_path: PathBuf,
    /// Snapshot of the row that will be flipped into `[packages]`
    /// on commit. Stored as JSON so the WAL can carry the same
    /// shape `manifest.toml` writes without depending on the
    /// `manifest` module's strong types — keeps the WAL forward-
    /// compatible if the manifest schema gains additive fields.
    pub new_row_json: serde_json::Value,
    /// `Some` for upgrades / uninstalls; `None` for fresh installs.
    pub prior_active_row_json: Option<serde_json::Value>,
    /// Snapshot of `[packages.*.commands]` and `[aliases]` entries
    /// for command names this transaction will touch. Used by the
    /// roll-back path.
    pub prior_command_ownership_json: serde_json::Value,
    /// New `[aliases]` entries this transaction will write on commit,
    /// keyed by exposed alias name. Empty for installs that don't
    /// resolve a command-name collision via `--alias`. Stored as JSON
    /// so the WAL stays forward-compatible if the alias schema grows
    /// additive fields. Required for roll-forward correctness — alias
    /// rows live outside `new_row_json` per the manifest schema, so
    /// recovery would otherwise silently lose them.
    ///
    /// `#[serde(default)]` so old WAL files written before this field
    /// existed still deserialize cleanly during recovery on first
    /// startup after upgrade.
    #[serde(default)]
    pub new_aliases_json: serde_json::Value,
    /// Phase 37 M4.2: explicit, typed list of ownership mutations this
    /// transaction will apply. Recovery replays this list directly
    /// rather than diff-deriving from pre/post manifest states — per
    /// the M4 audit, diff-based reconstruction is fragile and the
    /// intent should be the source of truth.
    ///
    /// Populated by `commit_locked` when the user resolved one or more
    /// command-name collisions via `--replace-bin` / `--alias` / the
    /// TTY prompt. Empty for installs with no collisions. Each entry
    /// is independently applicable; recovery iterates in order.
    ///
    /// `#[serde(default)]` so pre-M4.2 WAL files (empty by definition)
    /// deserialize cleanly.
    #[serde(default)]
    pub ownership_delta: Vec<OwnershipChange>,
}

/// One ownership mutation applied during commit and replayed during
/// recovery. See the M4 section of the phase-37 plan for the full
/// model. Each variant carries everything needed to (a) apply the
/// mutation idempotently in roll-forward and (b) undo it in roll-back.
///
/// Snapshot bodies inside are `serde_json::Value` rather than strong
/// types so the WAL stays forward-compatible with additive manifest
/// schema changes (matching the existing `new_row_json` /
/// `prior_active_row_json` pattern in `IntentPayload`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnershipChange {
    /// Transfer a directly-owned command from the old owner to the
    /// installing package. Roll-forward: drop `command` from
    /// `from_package.commands` (new package's `commands` list already
    /// includes it via the marker-derived active row). Roll-back: put
    /// `command` back into `from_package.commands` from the snapshot +
    /// re-emit their shim.
    DirectTransfer {
        /// The PATH name being transferred.
        command: String,
        /// Package that owned `command` before this transaction.
        from_package: String,
        /// Full PackageEntry of the displaced owner at Intent time.
        /// Shape: `{ "saved_spec": "...", "resolved": "...", ... }`.
        /// Used verbatim by roll-back to restore the pre-tx row.
        from_row_snapshot: serde_json::Value,
    },
    /// Remove an alias owned by another package so the installing
    /// package can take the PATH name as a direct bin. Roll-forward:
    /// drop `[aliases.<alias_name>]`. Roll-back: put it back from
    /// `entry_snapshot`. The colliding PATH name is the alias key —
    /// that's the primary key for both snapshot and restore.
    AliasOwnerRemove {
        /// The PATH name (alias key in `manifest.aliases`) being taken.
        alias_name: String,
        /// The AliasEntry being removed, shape `{ "package": "...",
        /// "bin": "..." }`. Roll-back inserts this verbatim.
        entry_snapshot: serde_json::Value,
    },
    /// Install a new alias entry pointing at a bin of the installing
    /// package. Roll-forward: write `[aliases.<alias_name>]` with the
    /// given `package` + `bin`. The `bin` field names the declared
    /// bin that is exposed via the alias and MUST be excluded from the
    /// new package's `commands` list (per the M4 manifest invariant:
    /// `commands` = directly-exposed names, aliased-away bins are
    /// tracked only via `[aliases]`). Roll-back: drop the alias row
    /// (no prior state to restore; it's a fresh install).
    AliasInstall {
        /// The PATH name the alias exposes.
        alias_name: String,
        /// Owner package (the package being installed).
        package: String,
        /// Declared bin name on `package` that the alias maps to.
        /// Excluded from `package.commands` on commit.
        bin: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WalRecord {
    /// Step 1 of an install/upgrade/uninstall transaction: the writer
    /// has decided what to do and is about to begin the slow extract /
    /// link work outside the tx-lock. Carries enough information for
    /// recovery to either roll forward (commit the pending row) or roll
    /// back (restore the prior active row + ownership).
    Intent(Box<IntentPayload>),

    /// Step 3 has finished: shims swapped, manifest flipped, all writes
    /// fsynced. The `tx_id` matches the originating Intent.
    Commit {
        tx_id: String,
        committed_at: chrono::DateTime<chrono::Utc>,
    },

    /// `validate_install_root` rejected the pending install; recovery
    /// has rolled back. The `tx_id` matches the originating Intent.
    Abort {
        tx_id: String,
        reason: String,
        aborted_at: chrono::DateTime<chrono::Utc>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxKind {
    Install,
    Upgrade,
    Uninstall,
}

// ─── Writer ───────────────────────────────────────────────────────────

/// Append-only writer for a WAL file at a fixed path. Each `append`
/// call writes one framed record and `fsync`s the file. Caller is
/// responsible for holding the global tx-lock; this writer does not
/// arbitrate concurrent appenders.
pub struct WalWriter {
    path: PathBuf,
    file: std::fs::File,
}

impl WalWriter {
    /// Open or create the WAL at `path`, seeking to EOF for append-only
    /// writes. Creates the parent directory if missing.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, WalError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        // Defensive: append mode positions writes at EOF on every write,
        // but seek so any caller introspecting `file.stream_position()`
        // sees a sensible value.
        file.seek(SeekFrom::End(0))?;
        Ok(WalWriter { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one framed record. The payload is serialized JSON of
    /// `record`; the on-disk shape is `len|crc|payload|sentinel`.
    /// The file is `sync_all()`-ed before return so the record is
    /// durable on platforms that honour fsync.
    pub fn append(&mut self, record: &WalRecord) -> Result<(), WalError> {
        let payload = serde_json::to_vec(record)?;
        let len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| WalError::PayloadTooLarge(payload.len()))?;
        let crc = crc32fast::hash(&payload);

        // Build the full frame in memory so a single write() call hits
        // the kernel — reduces (does not eliminate) torn-write risk
        // since most kernels honour write atomicity for buffers below
        // PIPE_BUF / page size. The recovery layer handles the
        // remaining cases by design.
        let mut frame = Vec::with_capacity(8 + payload.len() + 1);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&crc.to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.push(RECORD_SENTINEL);

        self.file.write_all(&frame)?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Truncate the WAL to zero bytes. Used by the post-recovery
    /// compaction path when no uncommitted records remain.
    pub fn truncate_to_zero(&mut self) -> Result<(), WalError> {
        self.file.set_len(0)?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    /// Truncate the WAL to `offset`. Used by the recovery path to
    /// discard a torn tail returned by [`WalReader::scan`]. Fsyncs the
    /// file after truncation.
    pub fn truncate_to(&mut self, offset: u64) -> Result<(), WalError> {
        self.file.set_len(offset)?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

// ─── Reader ───────────────────────────────────────────────────────────

/// Why a WAL scan stopped. The recovery layer's truncate-or-bail
/// decision depends on this — it must NOT truncate when the cause is a
/// record format we just don't recognize (which is data, not damage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStop {
    /// Reached EOF cleanly. `last_good_offset == file_len`.
    Eof,
    /// Framing failed at `offset`: insufficient bytes, length-prefix
    /// would overrun the file, CRC mismatch, missing sentinel, or
    /// malformed JSON. Caller should `truncate_to(last_good_offset)`
    /// to discard the torn tail.
    TornTail { offset: u64 },
    /// A well-framed record with an `op` value this binary doesn't
    /// recognize, at `offset`. Caller MUST NOT truncate — that would
    /// destroy state written by a newer `lpm`. Recovery should bail
    /// out with a "WAL written by newer lpm; upgrade required" error
    /// and leave the manifest / install roots untouched.
    UnknownOp { offset: u64, op: String },
}

/// Result of scanning a WAL file. `records` are every successfully
/// parsed record in order; `last_good_offset` is the byte offset
/// *after* the last good record (== `file_len` if the WAL is fully
/// well-formed). `stop` records why the scan ended — in particular,
/// whether the bytes after `last_good_offset` are torn-and-droppable
/// or unknown-but-precious (see [`ScanStop`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalScan {
    pub records: Vec<WalRecord>,
    pub last_good_offset: u64,
    pub file_len: u64,
    pub stop: ScanStop,
}

impl WalScan {
    /// True if the scan ended at clean EOF.
    pub fn is_clean(&self) -> bool {
        matches!(self.stop, ScanStop::Eof)
    }

    /// True when the bytes after `last_good_offset` should be discarded
    /// by recovery (framing failure, not unknown-op).
    pub fn has_torn_tail(&self) -> bool {
        matches!(self.stop, ScanStop::TornTail { .. })
    }

    /// True when the scan stopped at an unknown record variant. Recovery
    /// must NOT truncate the WAL in this case — the bytes past
    /// `last_good_offset` are state written by a newer lpm.
    pub fn hit_unknown_op(&self) -> bool {
        matches!(self.stop, ScanStop::UnknownOp { .. })
    }
}

/// Read-only scanner for an on-disk WAL.
pub struct WalReader {
    path: PathBuf,
}

impl WalReader {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        WalReader { path: path.into() }
    }

    /// Walk every record in the WAL. Stops at the first framing
    /// failure (insufficient bytes, length-prefix overrun, CRC
    /// mismatch, missing sentinel, malformed JSON) OR the first
    /// well-framed record with an `op` value this binary doesn't
    /// recognize. The two cases are reported via [`ScanStop`] so the
    /// recovery layer can apply the right policy — torn-tail truncates,
    /// unknown-op refuses to mutate state.
    ///
    /// Returns an `Eof` scan with empty `records` and zero offsets for
    /// a missing or empty file — both are valid no-op states.
    pub fn scan(&self) -> Result<WalScan, WalError> {
        let mut file = match std::fs::OpenOptions::new().read(true).open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(WalScan {
                    records: Vec::new(),
                    last_good_offset: 0,
                    file_len: 0,
                    stop: ScanStop::Eof,
                });
            }
            Err(e) => return Err(WalError::Io(e)),
        };

        let file_len = file.metadata()?.len();
        if file_len == 0 {
            return Ok(WalScan {
                records: Vec::new(),
                last_good_offset: 0,
                file_len,
                stop: ScanStop::Eof,
            });
        }

        // Read the whole file into memory. WALs are bounded in size by
        // the M3 rotation policy (default 10MB cap, see plan open Q13).
        let mut buf = Vec::with_capacity(file_len as usize);
        file.read_to_end(&mut buf)?;

        let mut records = Vec::new();
        let mut offset: usize = 0;
        let mut last_good_offset: usize = 0;
        let mut stop = ScanStop::Eof;

        while offset < buf.len() {
            // Need at least header (8) + sentinel (1) bytes to attempt a
            // record. Anything less is a torn tail.
            if buf.len() - offset < MIN_RECORD_BYTES {
                stop = ScanStop::TornTail {
                    offset: offset as u64,
                };
                break;
            }

            let len_bytes: [u8; 4] = buf[offset..offset + 4].try_into().expect("4 bytes");
            let crc_bytes: [u8; 4] = buf[offset + 4..offset + 8].try_into().expect("4 bytes");
            let payload_len = u32::from_be_bytes(len_bytes) as usize;
            let stored_crc = u32::from_be_bytes(crc_bytes);

            let frame_end = offset
                .checked_add(8)
                .and_then(|x| x.checked_add(payload_len))
                .and_then(|x| x.checked_add(1));
            let Some(frame_end) = frame_end else {
                stop = ScanStop::TornTail {
                    offset: offset as u64,
                };
                break;
            };
            if frame_end > buf.len() {
                stop = ScanStop::TornTail {
                    offset: offset as u64,
                };
                break;
            }

            let payload = &buf[offset + 8..offset + 8 + payload_len];
            let actual_crc = crc32fast::hash(payload);
            if actual_crc != stored_crc {
                tracing::debug!(
                    "wal: CRC mismatch at offset {} (stored={:#010x}, actual={:#010x})",
                    offset,
                    stored_crc,
                    actual_crc
                );
                stop = ScanStop::TornTail {
                    offset: offset as u64,
                };
                break;
            }
            if buf[offset + 8 + payload_len] != RECORD_SENTINEL {
                tracing::debug!("wal: missing sentinel at offset {}", offset);
                stop = ScanStop::TornTail {
                    offset: offset as u64,
                };
                break;
            }

            // Two-phase parse: validate JSON shape and `op` discriminator
            // first, then attempt the strongly-typed deserialize. This
            // lets us distinguish "torn / corrupt" from "valid but
            // unknown variant" — critical because they require opposite
            // recovery actions (truncate vs. bail-out).
            let value: serde_json::Value = match serde_json::from_slice(payload) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("wal: malformed JSON at offset {}: {}", offset, e);
                    stop = ScanStop::TornTail {
                        offset: offset as u64,
                    };
                    break;
                }
            };
            let op = match value.get("op").and_then(|v| v.as_str()) {
                Some(op) => op,
                None => {
                    // No op tag — the JSON is well-formed but not a
                    // WalRecord at all. Treat as corrupt; truncating
                    // is safer than refusing recovery on garbage data.
                    stop = ScanStop::TornTail {
                        offset: offset as u64,
                    };
                    break;
                }
            };
            if !is_known_op(op) {
                stop = ScanStop::UnknownOp {
                    offset: offset as u64,
                    op: op.to_string(),
                };
                break;
            }

            // Op is known to us — strongly-typed deserialize must succeed.
            // If it doesn't, the on-disk shape of a known variant has
            // diverged from this binary's expectation, which is a real
            // bug rather than a torn tail.
            let record: WalRecord = serde_json::from_value(value).map_err(WalError::Serialize)?;
            records.push(record);
            last_good_offset = frame_end;
            offset = frame_end;
        }

        Ok(WalScan {
            records,
            last_good_offset: last_good_offset as u64,
            file_len,
            stop,
        })
    }
}

/// Set of `op` discriminator values this binary knows how to deserialize.
/// Kept in sync with [`WalRecord`]. When adding a new variant, add its
/// snake_case op string here. The function is named so the serde
/// rename rules and this list are obviously paired in code review.
fn is_known_op(op: &str) -> bool {
    matches!(op, "intent" | "commit" | "abort")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn intent(tx_id: &str, package: &str) -> WalRecord {
        WalRecord::Intent(Box::new(IntentPayload {
            tx_id: tx_id.into(),
            kind: TxKind::Install,
            package: package.into(),
            new_root_path: PathBuf::from(format!("/tmp/installs/{package}@1.0.0")),
            new_row_json: serde_json::json!({"resolved": "1.0.0"}),
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({}),
            ownership_delta: Vec::new(),
        }))
    }

    fn commit(tx_id: &str) -> WalRecord {
        WalRecord::Commit {
            tx_id: tx_id.into(),
            committed_at: "2026-04-15T00:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn round_trip_single_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 1);
        assert!(scan.is_clean());
        assert!(!scan.has_torn_tail());
        assert!(!scan.hit_unknown_op());
        assert_eq!(scan.last_good_offset, scan.file_len);
    }

    /// Frame an arbitrary JSON payload into a well-formed WAL record
    /// (correct len + CRC + sentinel) and append it to `path`. Used by
    /// the unknown-op tests to inject a record this binary doesn't
    /// know how to deserialize without going through `WalRecord` first.
    fn append_raw_record(path: &Path, payload_json: &str) {
        let payload = payload_json.as_bytes();
        let len: u32 = payload.len() as u32;
        let crc = crc32fast::hash(payload);
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(&len.to_be_bytes()).unwrap();
        f.write_all(&crc.to_be_bytes()).unwrap();
        f.write_all(payload).unwrap();
        f.write_all(&[RECORD_SENTINEL]).unwrap();
    }

    #[test]
    fn unknown_op_stops_scan_with_unknown_op_marker_not_torn_tail() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();
        let good_offset = std::fs::metadata(&path).unwrap().len();

        // Inject a well-framed record with an op string this binary
        // doesn't recognize — what a future lpm version would emit.
        append_raw_record(&path, r#"{"op":"split","tx_id":"tx2"}"#);

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 1, "first known record still readable");
        assert!(!scan.has_torn_tail(), "must not be classified as torn");
        assert!(scan.hit_unknown_op(), "must be flagged as unknown-op");
        assert!(!scan.is_clean(), "scan did not reach clean EOF");
        match &scan.stop {
            ScanStop::UnknownOp { offset, op } => {
                assert_eq!(*offset, good_offset);
                assert_eq!(op, "split");
            }
            other => panic!("expected UnknownOp, got {other:?}"),
        }
    }

    #[test]
    fn unknown_op_does_not_advance_last_good_offset() {
        // Recovery must NOT truncate when the cause is unknown-op —
        // the bytes past last_good_offset are state written by a
        // newer lpm. Verifying last_good_offset stays at the boundary
        // of the last known record.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();
        let after_first = std::fs::metadata(&path).unwrap().len();
        append_raw_record(&path, r#"{"op":"future_variant","tx_id":"tx2"}"#);

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.last_good_offset, after_first);
        assert!(scan.last_good_offset < scan.file_len);
    }

    #[test]
    fn missing_op_field_is_classified_as_torn_tail() {
        // A well-framed record with valid CRC + sentinel but no `op`
        // field is treated as corrupt, not as an unknown variant.
        // The whole point of unknown-op detection is to recognize
        // *valid* future records; opless garbage doesn't qualify.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();
        append_raw_record(&path, r#"{"tx_id":"tx2","not_an_op":"oops"}"#);

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 1);
        assert!(scan.has_torn_tail());
        assert!(!scan.hit_unknown_op());
    }

    #[test]
    fn round_trip_many_records_preserves_order() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        for i in 0..50 {
            w.append(&intent(&format!("tx{i}"), "eslint")).unwrap();
        }
        for i in 0..50 {
            w.append(&commit(&format!("tx{i}"))).unwrap();
        }

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 100);
        assert!(matches!(scan.records[0], WalRecord::Intent { .. }));
        assert!(matches!(scan.records[50], WalRecord::Commit { .. }));
    }

    #[test]
    fn missing_file_scan_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let scan = WalReader::at(tmp.path().join("nope")).scan().unwrap();
        assert!(scan.records.is_empty());
        assert_eq!(scan.last_good_offset, 0);
        assert_eq!(scan.file_len, 0);
        assert!(scan.is_clean());
    }

    #[test]
    fn empty_file_scan_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        std::fs::write(&path, b"").unwrap();
        let scan = WalReader::at(&path).scan().unwrap();
        assert!(scan.records.is_empty());
        assert!(scan.is_clean());
    }

    #[test]
    fn truncated_in_header_torn_tail_detected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();

        // Append a partial header (4 of 8 bytes) — simulates kill -9
        // mid-header.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0, 0, 0, 1])
            .unwrap();

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 1, "first record still readable");
        assert!(scan.has_torn_tail());
        assert!(scan.last_good_offset < scan.file_len);
    }

    #[test]
    fn truncated_in_payload_torn_tail_detected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();

        // Manually frame a "partial payload" record: claim 100 bytes of
        // payload but only write 10.
        let payload = vec![b'x'; 10];
        let claimed_len: u32 = 100;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&claimed_len.to_be_bytes()).unwrap();
        f.write_all(&0u32.to_be_bytes()).unwrap(); // crc
        f.write_all(&payload).unwrap();

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 1);
        assert!(scan.has_torn_tail());
    }

    #[test]
    fn corrupted_crc_torn_tail_detected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();
        let good_offset = std::fs::metadata(&path).unwrap().len();

        w.append(&intent("tx2", "typescript")).unwrap();

        // Flip a byte in the second record's payload region.
        let mut buf = std::fs::read(&path).unwrap();
        let flip_at = (good_offset + 8 + 5) as usize; // 8 = header, 5 into payload
        buf[flip_at] ^= 0xFF;
        std::fs::write(&path, &buf).unwrap();

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 1, "corrupted record dropped");
        assert!(scan.has_torn_tail());
        assert_eq!(scan.last_good_offset, good_offset);
    }

    #[test]
    fn missing_sentinel_torn_tail_detected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();

        // Manually craft a record with the wrong sentinel byte.
        let payload = serde_json::to_vec(&intent("tx2", "typescript")).unwrap();
        let len: u32 = payload.len() as u32;
        let crc = crc32fast::hash(&payload);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&len.to_be_bytes()).unwrap();
        f.write_all(&crc.to_be_bytes()).unwrap();
        f.write_all(&payload).unwrap();
        f.write_all(&[0xFF]).unwrap(); // wrong sentinel

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 1);
        assert!(scan.has_torn_tail());
    }

    #[test]
    fn malformed_json_payload_torn_tail_detected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();

        // Frame a record with valid CRC + sentinel but garbage JSON.
        let payload = b"this is not json {{".to_vec();
        let len: u32 = payload.len() as u32;
        let crc = crc32fast::hash(&payload);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&len.to_be_bytes()).unwrap();
        f.write_all(&crc.to_be_bytes()).unwrap();
        f.write_all(&payload).unwrap();
        f.write_all(&[RECORD_SENTINEL]).unwrap();

        let scan = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan.records.len(), 1);
        assert!(scan.has_torn_tail());
    }

    #[test]
    fn truncate_to_discards_torn_tail_and_subsequent_scan_is_clean() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();
        w.append(&intent("tx2", "typescript")).unwrap();

        // Append garbage to simulate a torn third record.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[1, 2, 3])
            .unwrap();

        let scan = WalReader::at(&path).scan().unwrap();
        assert!(scan.has_torn_tail());

        // Recovery path: caller truncates to last_good_offset.
        w.truncate_to(scan.last_good_offset).unwrap();

        let rescan = WalReader::at(&path).scan().unwrap();
        assert_eq!(rescan.records.len(), 2);
        assert!(!rescan.has_torn_tail());
    }

    #[test]
    fn scan_is_idempotent_running_twice_yields_same_result() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        for i in 0..10 {
            w.append(&intent(&format!("tx{i}"), "eslint")).unwrap();
        }
        let scan1 = WalReader::at(&path).scan().unwrap();
        let scan2 = WalReader::at(&path).scan().unwrap();
        assert_eq!(scan1, scan2);
    }

    #[test]
    fn truncate_to_zero_is_clean_no_op_on_subsequent_scan() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let mut w = WalWriter::open(&path).unwrap();
        w.append(&intent("tx1", "eslint")).unwrap();
        w.append(&commit("tx1")).unwrap();
        w.truncate_to_zero().unwrap();

        let scan = WalReader::at(&path).scan().unwrap();
        assert!(scan.records.is_empty());
        assert_eq!(scan.file_len, 0);
    }

    #[test]
    fn record_variants_round_trip_through_json() {
        // Forward-compat property: the on-wire JSON shape stays stable.
        let recs = [
            intent("tx1", "eslint"),
            commit("tx1"),
            WalRecord::Abort {
                tx_id: "tx2".into(),
                reason: "validate_install_root failed".into(),
                aborted_at: "2026-04-15T00:00:00Z".parse().unwrap(),
            },
        ];
        for r in &recs {
            let bytes = serde_json::to_vec(r).unwrap();
            let parsed: WalRecord = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(*r, parsed);
        }
    }

    #[test]
    fn intent_round_trip_carries_new_aliases() {
        // Recovery depends on `new_aliases_json` to reconstruct the
        // post-commit `[aliases]` table. Verify the field round-trips
        // through serialize/deserialize.
        let r = WalRecord::Intent(Box::new(IntentPayload {
            tx_id: "tx1".into(),
            kind: TxKind::Install,
            package: "pkg-b".into(),
            new_root_path: PathBuf::from("/tmp/installs/pkg-b@1.0.0"),
            new_row_json: serde_json::json!({"resolved": "1.0.0"}),
            prior_active_row_json: None,
            prior_command_ownership_json: serde_json::json!({}),
            new_aliases_json: serde_json::json!({
                "srv": {"package": "pkg-b", "bin": "serve"}
            }),
            ownership_delta: Vec::new(),
        }));
        let bytes = serde_json::to_vec(&r).unwrap();
        let parsed: WalRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn old_intent_payload_without_new_aliases_field_still_deserializes() {
        // Before phase 37 M2 audit fix, IntentPayload had no
        // `new_aliases_json`. `#[serde(default)]` must let those
        // older payloads still parse during the first recovery on
        // a host upgrading across the field addition.
        let json = serde_json::json!({
            "op": "intent",
            "tx_id": "tx-old",
            "kind": "install",
            "package": "eslint",
            "new_root_path": "/tmp/installs/eslint@9.0.0",
            "new_row_json": {"resolved": "9.0.0"},
            "prior_active_row_json": null,
            "prior_command_ownership_json": {},
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let parsed: WalRecord = serde_json::from_slice(&bytes).unwrap();
        match parsed {
            WalRecord::Intent(p) => {
                // Default value for serde_json::Value is Value::Null.
                assert_eq!(p.new_aliases_json, serde_json::Value::Null);
            }
            _ => panic!("expected Intent"),
        }
    }

    #[test]
    fn writer_path_returns_what_was_opened() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("wal.jsonl");
        let w = WalWriter::open(&path).unwrap();
        assert_eq!(w.path(), path);
    }
}
