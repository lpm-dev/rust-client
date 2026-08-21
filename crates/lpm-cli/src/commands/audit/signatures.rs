use std::path::Path;
use std::sync::Arc;

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

use crate::install_ui;

use super::discovery::{self, DiscoveryResult, ManagerKind};

pub async fn run_signatures(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let discovery = discovery::discover_packages_retaining_lpm_lockfile(project_dir)?;
    let inputs = registry_signature_inputs_from_discovery(discovery)?;
    let route_table = lpm_registry::RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    let report = crate::registry_signatures::verify_packages(
        Arc::new(client.clone_with_config()),
        route_table,
        inputs,
        true,
    )
    .await;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.to_json()).unwrap()
        );
    } else {
        print_registry_signature_report(&report);
    }

    if report.has_failures() {
        return Err(LpmError::ExitCode(1));
    }
    Ok(())
}

fn registry_signature_inputs_from_discovery(
    discovery: DiscoveryResult,
) -> Result<Vec<crate::registry_signatures::RegistrySignatureInput>, LpmError> {
    if discovery.manager == ManagerKind::Lpm {
        let lockfile = discovery.lpm_lockfile.ok_or_else(|| {
            LpmError::Script("signature discovery did not retain its LPM lockfile snapshot".into())
        })?;
        let lockfile = Arc::try_unwrap(lockfile).unwrap_or_else(|lockfile| (*lockfile).clone());
        return Ok(lockfile
            .packages
            .into_iter()
            .map(
                |package| crate::registry_signatures::RegistrySignatureInput {
                    name: package.name,
                    version: package.version,
                    source: package.source,
                    resolved_url: None,
                    integrity: package.integrity,
                    signatures: package
                        .registry_signatures
                        .into_iter()
                        .map(|signature| lpm_registry::RegistrySignature {
                            keyid: signature.keyid,
                            sig: signature.sig,
                        })
                        .collect(),
                    published_at: package.registry_published_at,
                },
            )
            .collect());
    }

    Ok(discovery
        .packages
        .into_iter()
        .map(
            |package| crate::registry_signatures::RegistrySignatureInput {
                name: package.name,
                version: package.version,
                source: None,
                resolved_url: package.resolved_url,
                integrity: package.integrity,
                signatures: Vec::new(),
                published_at: None,
            },
        )
        .collect())
}

fn print_registry_signature_report(report: &crate::registry_signatures::RegistrySignatureReport) {
    if report.has_failures() {
        install_ui::warn_untrusted(&format!(
            "Registry signatures · {} verified · {} not verified",
            report.verified(),
            report.not_verified()
        ));
        for package in report.not_verified_packages() {
            let reason = package
                .reason
                .as_ref()
                .map_or_else(|| "not verified".to_string(), |reason| reason.human());
            let package_id = package.package_id();
            let package_id = lpm_common::sanitize_terminal_inline(&package_id);
            let reason = lpm_common::sanitize_terminal_inline(&reason);
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "  {}  {}",
                install_ui::yellow(&package_id),
                reason,
            ));
        }
    } else {
        install_ui::done_untrusted(&format!(
            "Registry signatures verified · {} verified",
            report.verified()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::audit::discovery::{DiscoveredPackage, ScanMode};

    #[test]
    fn lpm_signature_inputs_preserve_persisted_signature_evidence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"signature-evidence","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("lpm.lock"),
            format!(
                r#"[metadata]
lockfile-version = {}
resolved-with = "pubgrub"

[[packages]]
name = "signed-pkg"
version = "1.0.0"
source = "registry+https://registry.npmjs.org"
integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
registry-published-at = "2025-01-01T00:00:00.000Z"

[[packages.registry-signatures]]
keyid = "SHA256:test"
sig = "MEQCIEvidence"
"#,
                lpm_lockfile::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS
            ),
        )
        .unwrap();

        let discovery = discovery::discover_packages_retaining_lpm_lockfile(dir.path()).unwrap();
        let inputs = registry_signature_inputs_from_discovery(discovery).unwrap();

        assert_eq!(inputs.len(), 1);
        assert_eq!(
            inputs[0].published_at.as_deref(),
            Some("2025-01-01T00:00:00.000Z")
        );
        assert_eq!(inputs[0].signatures.len(), 1);
        assert_eq!(
            inputs[0].signatures[0].keyid.as_deref(),
            Some("SHA256:test")
        );
        assert_eq!(
            inputs[0].signatures[0].sig.as_deref(),
            Some("MEQCIEvidence")
        );
    }

    #[test]
    fn foreign_signature_inputs_preserve_recorded_registry_origin() {
        let discovery = DiscoveryResult {
            manager: ManagerKind::Npm,
            lockfile_path: None,
            project_root: std::path::PathBuf::new(),
            is_degraded: false,
            is_yarn_pnp: false,
            packages: vec![DiscoveredPackage {
                name: "private-pkg".to_string(),
                version: "1.0.0".to_string(),
                instance_id: None,
                path: "node_modules/private-pkg".to_string(),
                integrity: Some("sha512-private".to_string()),
                patch_sha256: None,
                resolved_url: Some(
                    "https://registry.example.test/private-pkg/-/private-pkg-1.0.0.tgz".to_string(),
                ),
                local_source_dir: None,
                scan_mode: ScanMode::LocalMissing,
                is_dev: false,
                is_optional: false,
                dependencies: Vec::new(),
            }],
            lpm_lockfile: None,
            lpm_lockfile_content: None,
            workspace_root: None,
        };

        let inputs = registry_signature_inputs_from_discovery(discovery).unwrap();

        assert_eq!(inputs[0].source.as_deref(), None);
        assert_eq!(
            inputs[0].resolved_url.as_deref(),
            Some("https://registry.example.test/private-pkg/-/private-pkg-1.0.0.tgz")
        );
    }
}
