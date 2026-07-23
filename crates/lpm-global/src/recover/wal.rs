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
    let relative = abs_path.strip_prefix(root.global_root()).ok()?;
    let mut serialized = String::with_capacity(relative.as_os_str().len());
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            return None;
        };
        if !serialized.is_empty() {
            serialized.push('/');
        }
        serialized.push_str(&segment.to_string_lossy());
    }
    (!serialized.is_empty()).then_some(serialized)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_install_root_uses_platform_independent_separators() {
        let temp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(temp.path());
        let install_root = root.global_root().join("installs").join("pkg@1.0.0");

        assert_eq!(
            relative_install_root(&root, &install_root),
            Some("installs/pkg@1.0.0".to_string())
        );
    }
}
