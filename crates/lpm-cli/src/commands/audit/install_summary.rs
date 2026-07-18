use std::path::Path;

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

use super::behavior::run_behavioral_analysis;
use super::discovery::{self, ScanMode};
use super::osv::run_osv_scan;
use super::registry::collect_registry_issues;
use super::types::{AuditCounts, AuditIssue, AuditResult};

/// Silent audit pass for the install pipeline's audit-after-install hook.
///
/// Mirrors the scan flow of [`run`] but never prints a human report —
/// the install pipeline composes its own slim one-line advisory from
/// the returned [`AuditCounts`]. Returns `Ok(None)` when discovery
/// found nothing to audit (fresh project, empty lockfile) so the
/// caller can skip the advisory entirely instead of printing a
/// misleading "Audited 0 packages" line.
///
/// **Failure mode:** scan-level errors (network down, missing store
/// lock, etc.) bubble up via `Result::Err`. The install pipeline
/// catches them and emits a degraded `! Audit skipped` line — they
/// never fail the install itself, matching the "audit findings are
/// informational" contract the operator opted into.
pub async fn run_install_summary(
    client: &RegistryClient,
    project_dir: &Path,
) -> Result<Option<AuditCounts>, LpmError> {
    let started = std::time::Instant::now();

    let discovery = discovery::discover_packages(project_dir)?;
    if discovery.packages.is_empty() {
        return Ok(None);
    }

    let total_packages = discovery.packages.len();
    let lpm_packages: Vec<(String, String)> = discovery
        .packages
        .iter()
        .filter(|p| p.name.starts_with("@lpm.dev/"))
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();

    // Re-use the same scan helpers `run` calls, but pass
    // `json_output=true` so every interior `if !json_output` print
    // gate stays closed — the install pipeline is the sole producer
    // of human output around this call.
    let mut results: Vec<AuditResult> = Vec::new();
    if !lpm_packages.is_empty() {
        let names: Vec<String> = lpm_packages.iter().map(|(n, _)| n.clone()).collect();
        let metadata_map = client.batch_metadata(&names).await.map_err(|error| {
            LpmError::Registry(format!(
                "LPM registry metadata lookup failed during audit-after-install: {error}"
            ))
        })?;
        for (name, version) in &lpm_packages {
            let metadata = metadata_map.get(name).ok_or_else(|| {
                LpmError::Registry(format!(
                    "LPM registry returned no metadata for installed package {name}@{version}"
                ))
            })?;
            let ver_meta = metadata.version(version).ok_or_else(|| {
                LpmError::Registry(format!(
                    "LPM registry metadata omitted installed version {name}@{version}"
                ))
            })?;
            let mut issues: Vec<AuditIssue> = Vec::new();
            collect_registry_issues(ver_meta, &mut issues);
            results.push(AuditResult {
                name: name.clone(),
                version: version.clone(),
                quality_score: ver_meta.quality_score,
                issues,
            });
        }
    }

    let needs_store_lock = discovery
        .packages
        .iter()
        .any(|p| matches!(p.scan_mode, ScanMode::RegistryAndStore));
    let behavioral_results = if needs_store_lock {
        let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
        let mut summary = None;
        lpm_common::with_shared_lock(lock_path, || {
            summary = Some(run_behavioral_analysis(
                &discovery,
                &mut results,
                &lpm_packages,
                /* json_output */ true,
                /* level */ None,
            ));
            Ok(())
        })?;
        summary.expect("set inside the closure body")
    } else {
        run_behavioral_analysis(
            &discovery,
            &mut results,
            &lpm_packages,
            /* json_output */ true,
            /* level */ None,
        )
    };

    let osv_outcome = run_osv_scan(
        &discovery.packages,
        /* json_output */ true,
        /* level */ None,
    )
    .await;
    if let Some(reason) = osv_outcome.degraded_reason {
        return Err(LpmError::Network(format!(
            "audit-after-install OSV scan did not complete: {reason}"
        )));
    }
    let registry_vulnerabilities = results
        .iter()
        .flat_map(|result| &result.issues)
        .filter(|issue| issue.category == "vulnerability")
        .count();

    Ok(Some(AuditCounts {
        packages_audited: total_packages,
        vulnerabilities: osv_outcome.vulns.len() + registry_vulnerabilities,
        suspicious: behavioral_results.packages_with_findings,
        elapsed_ms: started.elapsed().as_millis(),
    }))
}
