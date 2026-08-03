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
    let discovery = discovery::discover_packages(project_dir)?;
    let inputs = registry_signature_inputs_from_discovery(&discovery)?;
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
    discovery: &DiscoveryResult,
) -> Result<Vec<crate::registry_signatures::RegistrySignatureInput>, LpmError> {
    if discovery.manager == ManagerKind::Lpm {
        let lockfile = lpm_lockfile::Lockfile::read_for_project(&discovery.project_root)
            .map_err(|error| LpmError::Registry(format!("failed to read lpm.lock: {error}")))?;
        return Ok(lockfile
            .lockfile
            .packages
            .iter()
            .map(
                |package| crate::registry_signatures::RegistrySignatureInput {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    source: package.source.clone(),
                    integrity: package.integrity.clone(),
                    signatures: Vec::new(),
                    published_at: None,
                },
            )
            .collect());
    }

    Ok(discovery
        .packages
        .iter()
        .map(
            |package| crate::registry_signatures::RegistrySignatureInput {
                name: package.name.clone(),
                version: package.version.clone(),
                source: None,
                integrity: package.integrity.clone(),
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
