use super::*;
use std::fs::File;
use std::io::Read;

const AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE: &[u8] = b"auto-isolated-peer-conflicts = true";
const AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN: usize = AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE.len();
const LOCKFILE_PEER_CONFLICT_SCAN_CHUNK_SIZE: usize = 64 * 1024;

pub(super) fn resolve_strict_peer_dependencies(
    cli_override: Option<bool>,
    pkg: &lpm_workspace::PackageJson,
    global_config: &crate::commands::config::GlobalConfig,
) -> bool {
    cli_override
        .or_else(|| {
            pkg.lpm
                .as_ref()
                .and_then(|lpm| lpm.strict_peer_dependencies)
        })
        .or_else(|| global_config.get_bool("strict-peer-dependencies"))
        .unwrap_or(false)
}

pub(super) fn v2_linking_can_prepare_before_fetch(
    v2_mode: bool,
    serial_link: bool,
    has_targets_with_sri: bool,
    used_lockfile: bool,
    lockfile_peer_context_authoritative: bool,
) -> bool {
    v2_mode
        && !serial_link
        && has_targets_with_sri
        && (!used_lockfile || lockfile_peer_context_authoritative)
}

pub(super) fn strict_peer_dependency_error(
    peer_warnings: &[PeerWarning],
    peer_conflicts: &[PeerConflictReport],
) -> Option<LpmError> {
    if peer_warnings.is_empty() && peer_conflicts.is_empty() {
        return None;
    }

    let issue_count = peer_warnings.len() + peer_conflicts.len();
    let mut details = Vec::with_capacity(issue_count + 1);
    details.push(format!(
        "strict-peer-dependencies failed with {issue_count} issue(s)"
    ));
    details.extend(peer_warnings.iter().map(|warning| format!("- {warning}")));
    details.extend(peer_conflicts.iter().map(|conflict| {
        let unsatisfied = conflict
            .unsatisfied_consumers
            .iter()
            .map(|(consumer, range)| format!("{consumer} wants {range}"))
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "- peer conflict: {} pinned to {} but {} unsatisfied consumer(s): {}",
            conflict.canonical,
            conflict.chosen_version,
            conflict.unsatisfied_consumers.len(),
            unsatisfied
        )
    }));

    Some(LpmError::PeerDependency(details.join("\n")))
}

pub(super) fn peer_warning_json_value(warning: &PeerWarning) -> serde_json::Value {
    let issue_type = if warning.resolved_version.is_some() {
        "bad"
    } else {
        "missing"
    };
    serde_json::json!({
        "type": issue_type,
        "package": warning.package.as_str(),
        "version": warning.version.as_str(),
        "peer": warning.peer.as_str(),
        "required_range": warning.required_range.as_str(),
        "resolved_version": warning.resolved_version.as_deref(),
    })
}

pub(super) fn peer_conflict_json_value(report: &PeerConflictReport) -> serde_json::Value {
    serde_json::json!({
        "canonical": report.canonical.as_str(),
        "chosen_version": report.chosen_version.as_str(),
        "unsatisfied_consumers": report
            .unsatisfied_consumers
            .iter()
            .map(|(consumer, range)| serde_json::json!({
                "consumer": consumer.as_str(),
                "range": range.as_str(),
            }))
            .collect::<Vec<_>>(),
    })
}

pub(super) fn peer_issues_json_value(
    peer_warnings: &[PeerWarning],
    peer_conflicts: &[PeerConflictReport],
) -> serde_json::Value {
    let mut missing = Vec::new();
    let mut bad = Vec::new();
    for warning in peer_warnings {
        let entry = peer_warning_json_value(warning);
        if warning.resolved_version.is_some() {
            bad.push(entry);
        } else {
            missing.push(entry);
        }
    }
    let conflicts: Vec<serde_json::Value> = peer_conflicts
        .iter()
        .map(peer_conflict_json_value)
        .collect();
    let missing_count = missing.len();
    let bad_count = bad.len();
    let conflicts_count = conflicts.len();
    let total_count = missing_count + bad_count + conflicts_count;

    serde_json::json!({
        "missing": missing,
        "bad": bad,
        "conflicts": conflicts,
        "intersections": [],
        "missing_count": missing_count,
        "bad_count": bad_count,
        "conflicts_count": conflicts_count,
        "intersections_count": 0,
        "total_count": total_count,
    })
}

pub(super) fn lockfile_has_auto_isolated_peer_conflicts(lockfile_path: &Path) -> bool {
    let Ok(file) = File::open(lockfile_path) else {
        return false;
    };
    reader_has_auto_isolated_peer_conflicts(file)
}

fn reader_has_auto_isolated_peer_conflicts(mut reader: impl Read) -> bool {
    let mut buffer = [0u8; LOCKFILE_PEER_CONFLICT_SCAN_CHUNK_SIZE];
    let mut carry = [0u8; AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN - 1];
    let mut carry_len = 0usize;

    loop {
        let bytes_read = match reader.read(&mut buffer) {
            Ok(0) => return false,
            Ok(bytes_read) => bytes_read,
            Err(_) => return false,
        };
        let chunk = &buffer[..bytes_read];
        if chunk_has_auto_isolated_peer_conflicts(&carry[..carry_len], chunk) {
            return true;
        }
        update_auto_isolated_peer_conflicts_scan_carry(&mut carry, &mut carry_len, chunk);
    }
}

fn chunk_has_auto_isolated_peer_conflicts(carry: &[u8], chunk: &[u8]) -> bool {
    if bytes_have_auto_isolated_peer_conflicts(chunk) {
        return true;
    }

    let max_tail = carry.len().min(AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN - 1);
    for tail_len in 1..=max_tail {
        let head_len = AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN - tail_len;
        if head_len <= chunk.len()
            && carry[carry.len() - tail_len..] == AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE[..tail_len]
            && chunk[..head_len] == AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE[tail_len..]
        {
            return true;
        }
    }

    false
}

fn bytes_have_auto_isolated_peer_conflicts(bytes: &[u8]) -> bool {
    if bytes.len() < AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN {
        return false;
    }

    let search_end = bytes.len() - AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN + 1;
    let mut offset = 0usize;
    while offset < search_end {
        let Some(pos) = bytes[offset..search_end]
            .iter()
            .position(|&byte| byte == AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE[0])
        else {
            return false;
        };
        let start = offset + pos;
        if bytes[start..start + AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN]
            == *AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE
        {
            return true;
        }
        offset = start + 1;
    }

    false
}

fn update_auto_isolated_peer_conflicts_scan_carry(
    carry: &mut [u8; AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN - 1],
    carry_len: &mut usize,
    chunk: &[u8],
) {
    let max = AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN - 1;
    if chunk.len() >= max {
        carry.copy_from_slice(&chunk[chunk.len() - max..]);
        *carry_len = max;
        return;
    }

    let old_keep = (*carry_len).min(max - chunk.len());
    if old_keep > 0 {
        carry.copy_within(*carry_len - old_keep..*carry_len, 0);
    }
    carry[old_keep..old_keep + chunk.len()].copy_from_slice(chunk);
    *carry_len = old_keep + chunk.len();
}

pub(super) fn binary_lockfile_needs_writeback(
    lockfile_path: &Path,
    lockfile: &lpm_lockfile::Lockfile,
) -> bool {
    if !lpm_lockfile::binary::binary_format_supports(lockfile) {
        return false;
    }

    let binary_path = lockfile_path.with_extension("lockb");
    if binary_lockfile_is_older_than_toml(lockfile_path, &binary_path) {
        return true;
    }

    match lpm_lockfile::BinaryLockfileReader::open(&binary_path) {
        Ok(Some(_)) => false,
        Ok(None) | Err(_) => true,
    }
}

pub(super) fn binary_lockfile_is_older_than_toml(lockfile_path: &Path, binary_path: &Path) -> bool {
    if !binary_path.exists() {
        return false;
    }
    match (
        lockfile_path.metadata().and_then(|m| m.modified()),
        binary_path.metadata().and_then(|m| m.modified()),
    ) {
        (Ok(toml_time), Ok(binary_time)) => binary_time < toml_time,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_has_auto_isolated_peer_conflicts_returns_false_when_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();

        let found = lockfile_has_auto_isolated_peer_conflicts(&dir.path().join("missing.lock"));

        assert!(!found);
    }

    #[test]
    fn lockfile_has_auto_isolated_peer_conflicts_returns_false_when_flag_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join("lpm.lock");
        std::fs::write(
            &lockfile_path,
            b"[metadata]\nlockfile-version = 1\nauto-isolated-peer-conflicts = false\n",
        )
        .unwrap();

        let found = lockfile_has_auto_isolated_peer_conflicts(&lockfile_path);

        assert!(!found);
    }

    #[test]
    fn lockfile_has_auto_isolated_peer_conflicts_finds_flag_spanning_read_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join("lpm.lock");
        let split = AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN / 2;
        let mut content = vec![b'x'; LOCKFILE_PEER_CONFLICT_SCAN_CHUNK_SIZE - split];
        content.extend_from_slice(&AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE[..split]);
        content.extend_from_slice(&AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE[split..]);
        std::fs::write(&lockfile_path, content).unwrap();

        let found = lockfile_has_auto_isolated_peer_conflicts(&lockfile_path);

        assert!(found);
    }

    #[test]
    fn reader_has_auto_isolated_peer_conflicts_stops_after_first_matching_chunk() {
        struct FailsAfterFirstRead {
            reads: usize,
        }

        impl std::io::Read for FailsAfterFirstRead {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                if self.reads > 1 {
                    return Err(std::io::Error::other(
                        "reader should not be polled after a match",
                    ));
                }

                let prefix = b"[metadata]\n";
                let bytes_read = prefix.len() + AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE_LEN;
                buf[..prefix.len()].copy_from_slice(prefix);
                buf[prefix.len()..bytes_read].copy_from_slice(AUTO_ISOLATED_PEER_CONFLICTS_NEEDLE);
                Ok(bytes_read)
            }
        }

        let mut reader = FailsAfterFirstRead { reads: 0 };

        let found = reader_has_auto_isolated_peer_conflicts(&mut reader);

        assert!(found);
        assert_eq!(reader.reads, 1);
    }
}
