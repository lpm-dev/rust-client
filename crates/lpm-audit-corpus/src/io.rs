use std::path::{Path, PathBuf};

use crate::report::markdown::build_report;
use crate::types::{AuditMetadata, BoxError, PackageAudit};

/// Persist the records JSON, the sidecar metadata JSON, and the
/// Markdown report in one go. All three are derived from the same
/// in-memory state, so a single helper keeps them in lockstep across
/// the audit / reclassify / enrich-l3-only paths.
pub(crate) fn persist_audit(
    results_path: &Path,
    report_path: &Path,
    audits: &[PackageAudit],
    metadata: &AuditMetadata,
) -> Result<(), BoxError> {
    std::fs::write(results_path, serde_json::to_vec_pretty(audits)?)?;
    let meta_path = sidecar_metadata_path(results_path);
    std::fs::write(&meta_path, serde_json::to_vec_pretty(metadata)?)?;
    let report = build_report(audits, metadata);
    std::fs::write(report_path, &report)?;
    println!(
        "wrote {} audit records → {}\nwrote metadata → {}\nwrote markdown report → {}",
        audits.len(),
        results_path.display(),
        meta_path.display(),
        report_path.display()
    );
    Ok(())
}

/// Sidecar metadata path: `<results>.meta.json`. Picked rather than
/// wrapping the records file so existing tooling that deserialises a
/// bare `Vec<PackageAudit>` keeps working.
pub(crate) fn sidecar_metadata_path(results_path: &Path) -> PathBuf {
    let mut s = results_path.as_os_str().to_owned();
    s.push(".meta.json");
    PathBuf::from(s)
}

/// Load the metadata sidecar if it exists, else default. Used by the
/// reclassify / enrich-l3-only paths so we preserve prior-run
/// metadata when the new pass doesn't itself invoke the advisor.
pub(crate) fn load_sidecar_metadata(results_path: &Path) -> AuditMetadata {
    let path = sidecar_metadata_path(results_path);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => AuditMetadata::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_metadata_path_appends_meta_json_to_results_path() {
        let path = sidecar_metadata_path(Path::new("/tmp/audit/results.json"));
        assert_eq!(path, PathBuf::from("/tmp/audit/results.json.meta.json"));
    }
}
