//! Phase 37 — global install state for `~/.lpm/global/`.
//!
//! This crate owns the on-disk shape of every machine-global file that
//! the install -g / uninstall -g / approve-scripts --global / global *
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

pub mod install_root;
pub mod manifest;
pub mod recover;
pub mod shim;
pub mod sweep;
pub mod trusted_deps;
pub mod wal;

pub use install_root::{
    InstallReadyMarker, InstallRootStatus, MARKER_SCHEMA_VERSION, read_marker,
    validate_install_root, write_marker,
};
pub use recover::{ReconciledTx, ReconciliationOutcome, RecoveryReport, UnknownOpError, recover};

pub use manifest::{
    AliasEntry, CommandCollision, CommandOwner, GlobalManifest, MANIFEST_FILENAME, PackageEntry,
    PackageSource, PendingEntry, SCHEMA_VERSION, find_command_collisions, read_for, read_manifest,
    write_for, write_manifest,
};
pub use shim::{
    EmittedShim, Shim, ShimError, artifacts_complete, emit_shim, expected_artifacts, remove_shim,
};
pub use sweep::{SweepFailure, SweepReport, sweep_tombstones, try_sweep_tombstones};
pub use trusted_deps::{
    GlobalTrustedDependencies, TrustMatch as GlobalTrustMatch, TrustedDependencyBinding,
    rich_key as global_trust_key,
};
pub use wal::{
    IntentPayload, OwnershipChange, ScanStop, TxKind, WalError, WalReader, WalRecord, WalScan,
    WalWriter,
};
