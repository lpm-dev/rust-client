use std::collections::BTreeSet;

use lpm_common::{LpmError, LpmRoot};

use crate::wal::{WalRecord, WalWriter};

/// Convert an absolute install root path into the relative form the
/// `manifest.tombstones` list expects (`installs/<name>@<ver>`).
/// Returns `None` if the path lives outside `root.global_root()` —
/// a defensive check; recovery will refuse to tombstone in that case
/// rather than write a path the gc sweeper would interpret as
/// untrusted.
pub(super) fn relative_install_root(root: &LpmRoot, abs_path: &std::path::Path) -> Option<String> {
    abs_path
        .strip_prefix(root.global_root())
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

pub(super) fn compact_wal_if_quiescent(
    wal_path: &std::path::Path,
    records: &[WalRecord],
) -> Result<bool, LpmError> {
    let mut intents = BTreeSet::new();
    let mut resolved = BTreeSet::new();
    for r in records {
        match r {
            WalRecord::Intent(p) => {
                intents.insert(p.tx_id.clone());
            }
            WalRecord::Commit { tx_id, .. } | WalRecord::Abort { tx_id, .. } => {
                resolved.insert(tx_id.clone());
            }
        }
    }
    if intents.is_subset(&resolved) && !records.is_empty() {
        let mut w = WalWriter::open(wal_path)?;
        w.truncate_to_zero()?;
        return Ok(true);
    }
    Ok(false)
}
