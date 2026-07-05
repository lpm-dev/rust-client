use lpm_common::LpmRoot;
use std::path::PathBuf;

const MAX_TX_ID_COMPONENT_LEN: usize = 128;

pub fn tx_lock_path(root: &LpmRoot, tx_id: &str) -> PathBuf {
    root.global_root()
        .join(".inflight")
        .join(format!("{}.lock", tx_id_path_component(tx_id)))
}

fn tx_id_path_component(tx_id: &str) -> String {
    let mut component = String::with_capacity(tx_id.len().min(MAX_TX_ID_COMPONENT_LEN));
    for ch in tx_id.chars().take(MAX_TX_ID_COMPONENT_LEN) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            component.push(ch);
        } else {
            component.push('_');
        }
    }
    if component.is_empty() {
        component.push('_');
    }
    component
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_lock_path_sanitizes_untrusted_tx_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        let path = tx_lock_path(&root, "../../tx:id");

        assert_eq!(
            path,
            root.global_root()
                .join(".inflight")
                .join("______tx_id.lock")
        );
    }
}
