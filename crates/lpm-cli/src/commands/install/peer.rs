use super::*;

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
    const NEEDLE: &[u8] = b"auto-isolated-peer-conflicts = true";
    let Ok(content) = std::fs::read(lockfile_path) else {
        return false;
    };
    content.windows(NEEDLE.len()).any(|window| window == NEEDLE)
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
