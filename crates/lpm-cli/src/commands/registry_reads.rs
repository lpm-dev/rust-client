use crate::output;
use lpm_common::{LpmError, PackageName};
use lpm_registry::{PackageMetadata, RegistryClient, RouteTable, UpstreamRoute};
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
            output::warn(warning);
        }
    }

    if let Some(tagged) = route_table.tls_overrides().strict_ssl.as_ref()
        && !tagged.value
    {
        output::warn(&format!(
            "strict-ssl=false in {}:{} — TLS certificate verification is \
			 DISABLED across ALL registries for this command. This is a \
			 security risk.",
            tagged.source, tagged.line
        ));
    }

    for warning in route_table.npmrc_security_warnings() {
        output::warn(warning);
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
        output::info(&summary);
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
    match context.client.get_npm_metadata_routed(package, route).await {
        Ok(metadata) => Ok((RoutedPackageRef::Registry(package.to_string()), metadata)),
        Err(LpmError::NotFound(_)) if !package.contains('/') => {
            let lpm_package = PackageName::parse(package)?;
            let metadata = context.client.get_package_metadata(&lpm_package).await?;
            Ok((RoutedPackageRef::Lpm(lpm_package), metadata))
        }
        Err(error) => Err(error),
    }
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
