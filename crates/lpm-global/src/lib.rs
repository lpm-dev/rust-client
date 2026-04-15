//! Phase 37 — global install state for `~/.lpm/global/`.
//!
//! This crate owns the on-disk shape of every machine-global file that
//! the install -g / uninstall -g / approve-builds --global / global *
//! command surface touches:
//!
//! - [`manifest`] — `manifest.toml` with `[packages]`, `[pending]`,
//!   `[aliases]`, `tombstones`.
//! - [`wal`] — framed write-ahead log for crash-safe transactions
//!   (length + CRC + sentinel framing — see `wal::format`).
//!
//! The install pipeline that *consumes* these primitives lives in
//! `lpm-cli` (M3); this crate is deliberately storage-only so the schema
//! and persistence rules have a single source of truth, independent of
//! the command-layer wiring.

pub mod manifest;
pub mod wal;

pub use manifest::{
    AliasEntry, CommandOwner, GlobalManifest, MANIFEST_FILENAME, PackageEntry, PackageSource,
    PendingEntry, SCHEMA_VERSION, read_for, read_manifest, write_for, write_manifest,
};
pub use wal::{
    IntentPayload, ScanStop, TxKind, WalError, WalReader, WalRecord, WalScan, WalWriter,
};
