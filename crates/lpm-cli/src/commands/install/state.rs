use super::*;

pub(super) fn write_post_install_hash(
    project_dir: &Path,
    linker_mode: lpm_linker::LinkerMode,
    object_integrity_policy: lpm_store::v2::ObjectIntegrityPolicy,
) {
    let pkg = std::fs::read_to_string(project_dir.join("package.json")).unwrap_or_default();
    let lock = std::fs::read_to_string(project_dir.join("lpm.lock")).unwrap_or_default();
    let file_link_bytes = crate::install_state::collect_file_link_manifest_bytes(project_dir, &pkg);
    let platform = lpm_store::v2::PlatformTuple::current();
    let hash = crate::install_state::compute_install_hash_v8(
        &pkg,
        &lock,
        &file_link_bytes,
        linker_mode,
        object_integrity_policy,
        &platform,
    );
    if let Err(e) = crate::install_state::write_install_hash_with_integrity_and_platform(
        project_dir,
        &hash,
        linker_mode,
        object_integrity_policy,
        &platform,
    ) {
        tracing::warn!(
            "failed to write `.lpm/install-hash` after install ({e}) — \
             the next freshness check will fall through to the slow path"
        );
    }
}

/// Empty installs still need the same durable on-disk markers the
/// freshness cache keys on: `lpm.lock`, `node_modules/`, and the
/// standard `lpm.lockb`/`.gitattributes` sidecar written by the main
/// lockfile path. Without these, the empty-deps short-circuit would
/// succeed once but never become warm-cache fresh, so every later
/// `lpm install`, `lpm dev`, and sync fast-lane probe would fall back
/// to the slow path despite the manifest already being fully applied.
pub(super) fn materialize_empty_install_artifacts(project_dir: &Path) -> Result<(), LpmError> {
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    lpm_lockfile::Lockfile::default()
        .write_all(&lockfile_path)
        .map_err(|e| LpmError::Registry(format!("failed to write empty lockfile: {e}")))?;

    lpm_lockfile::ensure_gitattributes(project_dir)
        .map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

    std::fs::create_dir_all(project_dir.join("node_modules")).map_err(LpmError::Io)?;
    Ok(())
}
