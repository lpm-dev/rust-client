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

    configure_read_context(client, route_table, top_level_specs, json_output)
}

pub fn prepare_direct_read_context(
    client: &RegistryClient,
    project_dir: &Path,
    query: &str,
    json_output: bool,
) -> Result<RoutedReadContext, LpmError> {
    let route_table = RouteTable::new(
        lpm_registry::RouteMode::Direct,
        lpm_registry::NpmrcConfig::load_from_filesystem(project_dir),
    )
    .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    configure_read_context(client, route_table, &[query.to_string()], json_output)
}

fn configure_read_context(
    client: &RegistryClient,
    route_table: RouteTable,
    top_level_specs: &[String],
    json_output: bool,
) -> Result<RoutedReadContext, LpmError> {
    let eager_origins = route_table.effective_registry_origins(
        top_level_specs,
        client.base_url(),
        client.npm_registry_url(),
    );
    configure_read_context_for_origins(client, route_table, &eager_origins, !json_output)
}

pub fn prepare_locked_read_context(
    client: &RegistryClient,
    project_dir: &Path,
    origins: &[lpm_registry::npmrc::OriginKey],
) -> Result<RoutedReadContext, LpmError> {
    let route_table = RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    configure_read_context_for_origins(client, route_table, origins, false)
}

/// Which of `client`'s registries a command reads. Their TLS clients build
/// up front, so a broken setting for one of them fails before any request;
/// a registry the command doesn't read never loads its per-origin TLS files
/// (a global `cafile=` loads with the `.npmrc` itself).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryReads {
    pub lpm: bool,
    pub npm: bool,
}

impl RegistryReads {
    pub const LPM: Self = Self {
        lpm: true,
        npm: false,
    };
    pub const NONE: Self = Self {
        lpm: false,
        npm: false,
    };
}

/// The route table that the `.npmrc` files in effect at `config_dir` define,
/// and `client` with their TLS settings (`cafile=`, `ca=`, `strict-ssl`,
/// per-origin certificates), for a command that reads a registry itself
/// rather than through `lpm install`. The registries in `reads` build their
/// TLS clients now; any other origin with settings of its own builds them
/// on first use.
///
/// Security warnings print now. The advisory `.npmrc` warnings and the TLS
/// summary wait for [`RoutedReadContext::announce`], which a command skips
/// for `--json` output or when its install step prints them itself.
pub fn prepare_registry_read_context(
    client: &RegistryClient,
    config_dir: &Path,
    reads: RegistryReads,
) -> Result<RoutedReadContext, LpmError> {
    let route_table = RouteTable::from_env_and_filesystem(config_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    configure_registry_read_context(client, route_table, reads)
}

/// [`prepare_registry_read_context`] with a route table the caller already
/// read.
pub fn configure_registry_read_context(
    client: &RegistryClient,
    route_table: RouteTable,
    reads: RegistryReads,
) -> Result<RoutedReadContext, LpmError> {
    let eager_origins: Vec<_> = [
        reads.lpm.then(|| client.base_url()),
        reads.npm.then(|| client.npm_registry_url()),
    ]
    .into_iter()
    .flatten()
    .filter_map(lpm_registry::npmrc::OriginKey::from_request_url)
    .collect();
    configure_read_context_for_origins(client, route_table, &eager_origins, false)
}

/// [`prepare_registry_read_context`] for the current directory, announced
/// unless the output is JSON: the client for a command that reads the LPM
/// registry without a project of its own.
pub fn registry_client_for_current_directory(
    client: &RegistryClient,
    json_output: bool,
) -> Result<RegistryClient, LpmError> {
    let current_dir = std::env::current_dir().map_err(LpmError::Io)?;
    registry_client_for_directory(client, &current_dir, RegistryReads::LPM, json_output)
}

/// `client` with the `.npmrc` TLS settings in effect at `config_dir`,
/// announced unless the output is JSON: the client for a command that sends
/// to a registry, or that builds its own HTTP clients from
/// [`RegistryClient::tls_client_builder_for`]. The registries in `reads`
/// load their TLS files now; any other origin loads them on first use.
pub fn registry_client_for_directory(
    client: &RegistryClient,
    config_dir: &Path,
    reads: RegistryReads,
    json_output: bool,
) -> Result<RegistryClient, LpmError> {
    let context = prepare_registry_read_context(client, config_dir, reads)?;
    if !json_output {
        context.announce();
    }
    Ok(context.client)
}

impl RoutedReadContext {
    /// Print the advisory `.npmrc` warnings and the effective TLS summary.
    pub fn announce(&self) {
        print_npmrc_advisories(&self.route_table);
        print_tls_summary(&self.client);
    }
}

/// Whether this process has yet to print the `.npmrc` security warning
/// `key`. A command that reads a registry and then installs loads the same
/// `.npmrc` settings again, and each load warns about them.
pub(crate) fn first_npmrc_security_warning(key: &str) -> bool {
    static SHOWN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    SHOWN
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key.to_owned())
}

/// The [`first_npmrc_security_warning`] key of a `strict-ssl=false` line,
/// which each command words for itself.
pub(crate) fn strict_ssl_warning_key(source: &str, line: usize) -> String {
    format!("strict-ssl\0{source}\0{line}")
}

fn print_npmrc_advisories(route_table: &RouteTable) {
    for warning in route_table.npmrc_warnings() {
        install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(warning));
    }
}

fn print_tls_summary(client: &RegistryClient) {
    if let Some(summary) = client.render_effective_tls_summary() {
        install_ui::phase_untrusted(&lpm_common::sanitize_terminal_inline(&summary));
    }
}

fn configure_read_context_for_origins(
    client: &RegistryClient,
    route_table: RouteTable,
    eager_origins: &[lpm_registry::npmrc::OriginKey],
    announce: bool,
) -> Result<RoutedReadContext, LpmError> {
    if announce {
        print_npmrc_advisories(&route_table);
    }

    if let Some(tagged) = route_table.tls_overrides().strict_ssl.as_ref()
        && !tagged.value
        && first_npmrc_security_warning(&strict_ssl_warning_key(&tagged.source, tagged.line))
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
        if first_npmrc_security_warning(warning) {
            install_ui::warn_untrusted(&lpm_common::sanitize_terminal_inline(warning));
        }
    }

    let configured_client = client
        .clone_with_config()
        .with_tls_overrides_for(route_table.tls_overrides(), eager_origins)?;

    if announce {
        print_tls_summary(&configured_client);
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
        validate_metadata_registry_base(context.client.base_url())?;
        let metadata = context
            .client
            .revalidate_package_metadata_with_timings(&lpm_package)
            .await?;
        return Ok((RoutedPackageRef::Lpm(lpm_package), metadata));
    }

    let route = context.route_table.route_for_package(package);
    let result = match route {
        UpstreamRoute::NpmDirect | UpstreamRoute::LpmWorker => {
            validate_metadata_registry_base(context.client.npm_registry_url())?;
            context
                .client
                .revalidate_npm_metadata_direct_with_timings(package)
                .await
        }
        UpstreamRoute::Custom { target, auth } => {
            validate_metadata_registry_base(&target.base_url)?;
            context
                .client
                .revalidate_npm_metadata_from_with_timings(
                    &target.base_url,
                    package,
                    auth.as_deref(),
                )
                .await
        }
    };
    // These reads send the .npmrc credential for their registry, never the
    // LPM session, so even when that registry is the LPM host a missing
    // credential is .npmrc's to supply.
    let metadata = result.map_err(|error| match error {
        LpmError::AuthRequired => LpmError::Registry(
            "info authentication failed. Configure credentials in .npmrc for the selected npm-compatible registry.".into(),
        ),
        error => error,
    })?;
    Ok((RoutedPackageRef::Registry(package.to_string()), metadata))
}

fn validate_metadata_registry_base(base_url: &str) -> Result<(), LpmError> {
    let parsed = reqwest::Url::parse(base_url)
        .map_err(|_| LpmError::Registry("invalid metadata registry URL".into()))?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(LpmError::Registry(
            "metadata registry URL must not contain a query or fragment".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_npmrc_security_warning_prints_once_per_process() {
        let key = "registry-reads-test: project .npmrc refused ca";
        assert!(first_npmrc_security_warning(key));
        assert!(!first_npmrc_security_warning(key));
        assert!(first_npmrc_security_warning(&strict_ssl_warning_key(
            "/a/.npmrc",
            1
        )));
        assert!(first_npmrc_security_warning(&strict_ssl_warning_key(
            "/a/.npmrc",
            2
        )));
        assert!(!first_npmrc_security_warning(&strict_ssl_warning_key(
            "/a/.npmrc",
            1
        )));
    }

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
