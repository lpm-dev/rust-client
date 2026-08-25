use crate::install_ui;
use lpm_common::{LpmError, PackageName};
use lpm_registry::{
    PackageMetadata, RegistryClient, RouteTable, TimedPackageMetadata, UpstreamRoute,
};
use std::path::Path;

pub struct RoutedReadContext {
    pub client: RegistryClient,
    pub route_table: RouteTable,
}

pub enum RoutedPackageRef {
    Lpm(PackageName),
    Registry(String),
}

impl RoutedPackageRef {
    pub fn route_name(&self) -> String {
        match self {
            Self::Lpm(package) => package.scoped(),
            Self::Registry(name) => name.clone(),
        }
    }
}

pub fn normalize_package_version_input<'a>(
    command: &str,
    package: &'a str,
    version: Option<&'a str>,
) -> Result<(&'a str, Option<&'a str>), LpmError> {
    let (name, inline_version) = split_package_and_inline_version(package);
    if name.is_empty() {
        return Err(LpmError::InvalidPackageName(format!(
            "could not parse package name from '{package}'"
        )));
    }

    if let (Some(inline_version), Some(flag_version)) = (inline_version, version) {
        return Err(LpmError::Script(format!(
            "version specified twice for {name}: positional spec uses '{inline_version}' and \
             --version uses '{flag_version}'. Use one form, for example \
             `lpm {command} {name}@{inline_version}` or `lpm {command} {name} --version {flag_version}`."
        )));
    }

    Ok((name, version.or(inline_version)))
}

fn split_package_and_inline_version(spec: &str) -> (&str, Option<&str>) {
    let (name, version) = if let Some(rest) = spec.strip_prefix('@') {
        match rest.find('@') {
            Some(at_pos) => {
                let split = at_pos + 1;
                (&spec[..split], Some(&spec[split + 1..]))
            }
            None => (spec, None),
        }
    } else {
        match spec.find('@') {
            Some(at_pos) => (&spec[..at_pos], Some(&spec[at_pos + 1..])),
            None => (spec, None),
        }
    };

    (name, version.filter(|value| !value.is_empty()))
}

pub fn prepare_routed_read_context(
    client: &RegistryClient,
    project_dir: &Path,
    top_level_specs: &[String],
    json_output: bool,
) -> Result<RoutedReadContext, LpmError> {
    let route_table = RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;

    if !json_output {
        for warning in route_table.npmrc_warnings() {
            install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(warning));
        }
    }

    if let Some(tagged) = route_table.tls_overrides().strict_ssl.as_ref()
        && !tagged.value
    {
        install_ui::warn_untrusted(&format!(
            "strict-ssl=false in {}:{} — TLS certificate verification is \
			 DISABLED across ALL registries for this command. This is a \
			 security risk.",
            lpm_common::sanitize_terminal_inline(&tagged.source),
            tagged.line
        ));
    }

    for warning in route_table.npmrc_security_warnings() {
        install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(warning));
    }

    let eager_origins = route_table.effective_registry_origins(
        top_level_specs,
        client.base_url(),
        client.npm_registry_url(),
    );
    let configured_client = client
        .clone_with_config()
        .with_tls_overrides_for(route_table.tls_overrides(), &eager_origins)?;

    if !json_output && let Some(summary) = configured_client.render_effective_tls_summary() {
        install_ui::phase_untrusted(&lpm_common::sanitize_terminal_inline(&summary));
    }

    Ok(RoutedReadContext {
        client: configured_client,
        route_table,
    })
}

pub async fn fetch_routed_package_metadata(
    context: &RoutedReadContext,
    package: &str,
) -> Result<(RoutedPackageRef, PackageMetadata), LpmError> {
    if package.starts_with("@lpm.dev/") {
        let lpm_package = PackageName::parse(package)?;
        let metadata = context.client.get_package_metadata(&lpm_package).await?;
        return Ok((RoutedPackageRef::Lpm(lpm_package), metadata));
    }

    let route = context.route_table.route_for_package(package);
    let metadata = context
        .client
        .get_npm_metadata_routed(package, route)
        .await?;
    Ok((RoutedPackageRef::Registry(package.to_string()), metadata))
}

pub async fn revalidate_routed_package_metadata(
    context: &RoutedReadContext,
    package: &str,
) -> Result<(RoutedPackageRef, TimedPackageMetadata), LpmError> {
    if package.starts_with("@lpm.dev/") {
        let lpm_package = PackageName::parse(package)?;
        let metadata = context
            .client
            .revalidate_package_metadata_with_timings(&lpm_package)
            .await?;
        return Ok((RoutedPackageRef::Lpm(lpm_package), metadata));
    }

    let route = context.route_table.route_for_package(package);
    let result = match route {
        UpstreamRoute::NpmDirect => {
            context
                .client
                .revalidate_npm_metadata_direct_with_timings(package)
                .await
        }
        UpstreamRoute::Custom { target, auth } => {
            context
                .client
                .revalidate_npm_metadata_from_with_timings(
                    &target.base_url,
                    package,
                    auth.as_deref(),
                )
                .await
        }
        UpstreamRoute::LpmWorker => {
            context
                .client
                .revalidate_npm_metadata_direct_with_timings(package)
                .await
        }
    };
    let metadata = result?;
    Ok((RoutedPackageRef::Registry(package.to_string()), metadata))
}

pub fn search_route_for_query(route_table: &RouteTable, query: &str) -> UpstreamRoute {
    if query.starts_with("@lpm.dev/") {
        return UpstreamRoute::LpmWorker;
    }

    match route_table.route_for_package(query) {
        UpstreamRoute::Custom { target, auth } => UpstreamRoute::Custom { target, auth },
        _ => UpstreamRoute::NpmDirect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_package_and_inline_version_handles_unscoped_npm_specs() {
        assert_eq!(
            normalize_package_version_input("info", "react@0.14.3", None).unwrap(),
            ("react", Some("0.14.3"))
        );
    }

    #[test]
    fn split_package_and_inline_version_handles_scoped_npm_specs() {
        assert_eq!(
            normalize_package_version_input("info", "@types/node@20.11.0", None).unwrap(),
            ("@types/node", Some("20.11.0"))
        );
    }

    #[test]
    fn split_package_and_inline_version_handles_scoped_lpm_specs() {
        assert_eq!(
            normalize_package_version_input("download", "@lpm.dev/owner.react@1.0.0", None)
                .unwrap(),
            ("@lpm.dev/owner.react", Some("1.0.0"))
        );
    }

    #[test]
    fn normalize_package_version_input_rejects_two_version_selectors() {
        let err = normalize_package_version_input("download", "react@0.14.3", Some("latest"))
            .unwrap_err();
        assert!(
            err.to_string().contains("version specified twice"),
            "duplicate selectors must fail clearly, got {err}"
        );
    }
}
