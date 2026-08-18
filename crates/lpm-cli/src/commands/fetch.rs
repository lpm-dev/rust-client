use crate::commands::install::{
    NpmFirewallMaterializationPackage, prepare_npm_firewall_materialization_preflight,
    run_prepared_npm_firewall_materialization_preflight,
};
use crate::install_ui;
use futures::{StreamExt, TryStreamExt};
use lpm_common::{LpmError, LpmRoot};
use lpm_lockfile::{LockedPackage, Source};
use lpm_registry::{RegistryClient, RouteTable};
use lpm_store::PackageStore;
use serde::Serialize;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

const DEFAULT_MAX_CONCURRENT_DOWNLOADS: usize = 24;

#[derive(Debug, Clone, Serialize)]
struct FetchPlatform {
    os: String,
    cpu: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    libc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FetchSource {
    Registry {
        registry_url: String,
        tarball_url: String,
    },
    RemoteTarball {
        url: String,
    },
    GitHub {
        url: String,
    },
}

impl FetchSource {
    fn url(&self) -> &str {
        match self {
            Self::Registry { tarball_url, .. } => tarball_url,
            Self::RemoteTarball { url } => url,
            Self::GitHub { url } => url,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Registry { .. } => "registry",
            Self::RemoteTarball { .. } => "remote_tarball",
            Self::GitHub { .. } => "git",
        }
    }
}

#[derive(Debug, Clone)]
struct FetchTarget {
    name: String,
    version: String,
    integrity: String,
    source: FetchSource,
}

#[derive(Debug, Eq)]
struct FetchArtifactKey {
    integrity: String,
    source: FetchSource,
}

impl PartialEq for FetchArtifactKey {
    fn eq(&self, other: &Self) -> bool {
        self.integrity == other.integrity && self.source == other.source
    }
}

impl Hash for FetchArtifactKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.integrity.hash(state);
        self.source.hash(state);
    }
}

#[derive(Debug)]
struct FetchWork {
    integrity: String,
    source: FetchSource,
    targets: Vec<FetchTarget>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum FetchPackageStatus {
    Fetched,
    Cached,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
struct FetchPackageResult {
    name: String,
    version: String,
    source: String,
    status: FetchPackageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
struct FetchCounts {
    total: usize,
    fetched: usize,
    cached: usize,
    skipped: usize,
}

#[derive(Debug, Serialize)]
struct FetchJsonSummary {
    success: bool,
    lockfile: &'static str,
    platform: FetchPlatform,
    counts: FetchCounts,
    packages: Vec<FetchPackageResult>,
    elapsed_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    firewall: Option<serde_json::Value>,
}

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    platform: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let started = Instant::now();
    let target_platform = match platform {
        Some(raw) => FetchPlatform::parse(raw)?,
        None => FetchPlatform::current(),
    };
    let lockfile = lpm_lockfile::Lockfile::read_for_project(project_dir)
        .map_err(|e| {
            LpmError::NotFound(format!(
                "no usable lpm.lock found. Run `lpm install` before `lpm fetch`: {e}"
            ))
        })?
        .lockfile;

    let mut targets = Vec::with_capacity(lockfile.packages.len());
    let mut results = Vec::new();
    for package in &lockfile.packages {
        match classify_package(package, &target_platform)? {
            FetchPlan::Fetch(target) => targets.push(target),
            FetchPlan::Skip(reason) => results.push(FetchPackageResult {
                name: package.name.clone(),
                version: package.version.clone(),
                source: source_label(package),
                status: FetchPackageStatus::Skipped,
                reason: Some(reason),
            }),
        }
    }

    let route_table = RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|error| LpmError::Registry(format!("npmrc: {error}")))?;
    emit_route_warnings(&route_table, json_output);

    let lpm_root = LpmRoot::from_env()?;
    let store = PackageStore::from_root(&lpm_root);
    let store_v2 = v2_store_for_fetch(&lpm_root)?;

    let firewall_packages = npm_firewall_packages_for_fetch_targets(&targets, client);
    let firewall_preflight = prepare_npm_firewall_materialization_preflight(
        project_dir,
        &firewall_packages,
        json_output,
    )?;

    if !json_output {
        let fetch_message = install_ui::TerminalLine::new("Fetching ")
            .yellow(&targets.len().to_string())
            .text(" package(s) from lpm.lock");
        install_ui::phase_line(install_ui::with_firewall_badge(
            fetch_message,
            firewall_preflight.is_active(),
        ));
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim(&format!("{:<12}", "platform:")),
            render_platform(&target_platform)
        ));
    }

    let firewall_json = run_prepared_npm_firewall_materialization_preflight(
        client,
        firewall_preflight,
        json_output,
    )
    .await?;

    let work = coalesce_fetch_targets(targets);
    let concurrency = max_concurrent_downloads();
    let eager_package_names = work
        .iter()
        .filter_map(|work| match &work.source {
            FetchSource::Registry { .. } => work.targets.first().map(|target| target.name.clone()),
            FetchSource::RemoteTarball { .. } | FetchSource::GitHub { .. } => None,
        })
        .collect::<Vec<_>>();
    let eager_origins = route_table.effective_registry_origins(
        &eager_package_names,
        client.base_url(),
        client.npm_registry_url(),
    );
    let client = Arc::new(
        client
            .clone_with_config()
            .with_tls_overrides_for(route_table.tls_overrides(), &eager_origins)?,
    );
    let route_table = Arc::new(route_table);
    let store = Arc::new(store);
    let fetched: Vec<Vec<FetchPackageResult>> = futures::stream::iter(work)
        .map(|work| {
            fetch_artifact(
                Arc::clone(&client),
                Arc::clone(&route_table),
                Arc::clone(&store),
                store_v2.clone(),
                work,
            )
        })
        .buffer_unordered(concurrency)
        .try_collect()
        .await?;
    results.extend(fetched.into_iter().flatten());

    results.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.source.cmp(&b.source))
    });
    let counts = count_results(&results);

    if json_output {
        let summary = FetchJsonSummary {
            success: true,
            lockfile: lpm_lockfile::LOCKFILE_NAME,
            platform: target_platform,
            counts,
            packages: results,
            elapsed_ms: started.elapsed().as_millis(),
            firewall: firewall_json,
        };
        println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    } else {
        if counts.skipped > 0 {
            install_ui::skipped_untrusted(&format!(
                "Skipped {} local/platform package(s)",
                counts.skipped
            ));
        }
        let elapsed = install_ui::format_duration(started.elapsed());
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · fetched {}, cached {}, skipped {} in {}",
            install_ui::green(&counts.fetched.to_string()),
            install_ui::green(&counts.cached.to_string()),
            install_ui::green(&counts.skipped.to_string()),
            install_ui::green(&elapsed)
        ));
    }

    Ok(())
}

fn v2_store_for_fetch(lpm_root: &LpmRoot) -> Result<Option<Arc<lpm_store::v2::Store>>, LpmError> {
    let store_version = lpm_store::StoreVersion::from_env();
    if !store_version.uses_virtual_store() {
        return Ok(None);
    }
    let global_config = crate::commands::config::GlobalConfig::load_checked()?;
    Ok(Some(configured_v2_store_for_fetch(
        lpm_root,
        &global_config,
        store_version,
    )?))
}

fn configured_v2_store_for_fetch(
    lpm_root: &LpmRoot,
    global_config: &crate::commands::config::GlobalConfig,
    store_version: lpm_store::StoreVersion,
) -> Result<Arc<lpm_store::v2::Store>, LpmError> {
    let object_integrity_policy =
        crate::commands::config::resolve_object_integrity_policy(global_config)?;
    Ok(Arc::new(
        lpm_store::v2::Store::from_lpm_root_for_version_with_object_integrity_policy(
            lpm_root,
            store_version,
            object_integrity_policy,
        ),
    ))
}

fn coalesce_fetch_targets(targets: Vec<FetchTarget>) -> Vec<FetchWork> {
    let mut artifacts: HashMap<FetchArtifactKey, Vec<FetchTarget>> =
        HashMap::with_capacity(targets.len());
    for target in targets {
        let key = FetchArtifactKey {
            integrity: target.integrity.clone(),
            source: target.source.clone(),
        };
        artifacts.entry(key).or_default().push(target);
    }
    artifacts
        .into_iter()
        .map(|(key, targets)| FetchWork {
            integrity: key.integrity,
            source: key.source,
            targets,
        })
        .collect()
}

async fn fetch_artifact(
    client: Arc<RegistryClient>,
    route_table: Arc<RouteTable>,
    store: Arc<PackageStore>,
    store_v2: Option<Arc<lpm_store::v2::Store>>,
    work: FetchWork,
) -> Result<Vec<FetchPackageResult>, LpmError> {
    let FetchWork {
        integrity,
        source,
        targets,
    } = work;
    let cached: Vec<bool> = targets
        .iter()
        .map(|target| is_cached(target, &store, store_v2.as_deref()))
        .collect();
    if cached.iter().all(|cached| *cached) {
        return Ok(targets
            .iter()
            .map(|target| result_for(target, FetchPackageStatus::Cached))
            .collect());
    }

    let routing_name = targets
        .first()
        .map(|target| target.name.as_str())
        .ok_or_else(|| LpmError::Registry("fetch artifact has no target packages".to_string()))?;
    let downloaded = match &source {
        FetchSource::GitHub { url } => {
            crate::commands::install::download_github_archive_to_file(url, Some(&integrity)).await?
        }
        FetchSource::Registry { .. } => {
            client
                .download_tarball_routed_with_integrity(
                    &route_table,
                    routing_name,
                    source.url(),
                    &integrity,
                )
                .await?
        }
        FetchSource::RemoteTarball { .. } => {
            client
                .download_tarball_to_file_with_auth_and_integrity(source.url(), None, &integrity)
                .await?
        }
    };

    let targets = tokio::task::spawn_blocking(move || -> Result<Vec<FetchTarget>, LpmError> {
        if let Some(store_v2) = store_v2 {
            store_v2.extract_object_from_file(downloaded.file.path(), &downloaded.sri)?;
        } else {
            match source {
                FetchSource::Registry { .. } => {
                    for target in &targets {
                        store.store_package_from_file(
                            &target.name,
                            &target.version,
                            downloaded.file.path(),
                            &downloaded.sri,
                        )?;
                    }
                }
                FetchSource::RemoteTarball { .. } | FetchSource::GitHub { .. } => {
                    store.store_tarball_at_cas_path_from_file(
                        &downloaded.sri,
                        downloaded.file.path(),
                    )?;
                }
            }
        }
        Ok(targets)
    })
    .await
    .map_err(|e| LpmError::Registry(format!("fetch store worker failed to join: {e}")))??;

    Ok(targets
        .iter()
        .zip(cached)
        .map(|(target, cached)| {
            result_for(
                target,
                if cached {
                    FetchPackageStatus::Cached
                } else {
                    FetchPackageStatus::Fetched
                },
            )
        })
        .collect())
}

fn emit_route_warnings(route_table: &RouteTable, json_output: bool) {
    if !json_output {
        for warning in route_table.npmrc_warnings() {
            crate::output::warn(&lpm_common::sanitize_terminal_inline(warning));
        }
    }
    if let Some(tagged) = route_table.tls_overrides().strict_ssl.as_ref()
        && !tagged.value
    {
        crate::output::warn(&format!(
            "strict-ssl=false in {}:{} — TLS certificate verification is DISABLED for this fetch across ALL registries. This is a security risk.",
            lpm_common::sanitize_terminal_inline(&tagged.source),
            tagged.line
        ));
    }
    for warning in route_table.npmrc_security_warnings() {
        crate::output::warn(&lpm_common::sanitize_terminal_inline(warning));
    }
}

fn classify_package(
    package: &LockedPackage,
    platform: &FetchPlatform,
) -> Result<FetchPlan, LpmError> {
    if !package_matches_platform(package, platform) {
        return Ok(FetchPlan::Skip("platform".to_string()));
    }

    let source = match package.source_kind() {
        Some(Ok(source)) => source,
        Some(Err(err)) => {
            return Err(LpmError::Registry(format!(
                "lpm.lock package {}@{} has invalid source: {err}",
                package.name, package.version
            )));
        }
        None => Source::Registry {
            url: "legacy".to_string(),
        },
    };

    match source {
        Source::Registry { url: registry_url } => {
            let integrity = required_integrity(package)?;
            let tarball_url = package.tarball.clone().ok_or_else(|| {
                LpmError::Registry(format!(
                    "lpm.lock package {}@{} is missing tarball URL; run `lpm install` to refresh the lockfile before `lpm fetch`",
                    package.name, package.version
                ))
            })?;
            Ok(FetchPlan::Fetch(FetchTarget {
                name: package.name.clone(),
                version: package.version.clone(),
                integrity,
                source: FetchSource::Registry {
                    registry_url,
                    tarball_url,
                },
            }))
        }
        Source::Tarball { url } if is_remote_tarball_url(&url) => {
            let integrity = required_integrity(package)?;
            Ok(FetchPlan::Fetch(FetchTarget {
                name: package.name.clone(),
                version: package.version.clone(),
                integrity,
                source: FetchSource::RemoteTarball { url },
            }))
        }
        Source::Tarball { .. } => Ok(FetchPlan::Skip("local_tarball".to_string())),
        Source::Directory { .. } | Source::Link { .. } => {
            Ok(FetchPlan::Skip("local_source".to_string()))
        }
        Source::Git { url } => {
            let integrity = required_integrity(package)?;
            let archive_url = crate::commands::install::github_archive_url(&url)?;
            Ok(FetchPlan::Fetch(FetchTarget {
                name: package.name.clone(),
                version: package.version.clone(),
                integrity,
                source: FetchSource::GitHub { url: archive_url },
            }))
        }
    }
}

#[derive(Debug)]
enum FetchPlan {
    Fetch(FetchTarget),
    Skip(String),
}

fn required_integrity(package: &LockedPackage) -> Result<String, LpmError> {
    package.integrity.clone().ok_or_else(|| {
        LpmError::Registry(format!(
            "lpm.lock package {}@{} is missing integrity; run `lpm install` to refresh the lockfile before `lpm fetch`",
            package.name, package.version
        ))
    })
}

fn is_cached(
    target: &FetchTarget,
    store: &PackageStore,
    store_v2: Option<&lpm_store::v2::Store>,
) -> bool {
    if let Some(store_v2) = store_v2 {
        return store_v2
            .reusable_object_dir(&target.integrity)
            .is_ok_and(|object_dir| object_dir.is_some());
    }

    match &target.source {
        FetchSource::Registry { .. } => store.has_package(&target.name, &target.version),
        FetchSource::RemoteTarball { .. } | FetchSource::GitHub { .. } => {
            store.has_tarball(&target.integrity)
        }
    }
}

fn npm_firewall_packages_for_fetch_targets(
    targets: &[FetchTarget],
    client: &RegistryClient,
) -> Vec<NpmFirewallMaterializationPackage> {
    let mut packages = Vec::with_capacity(targets.len());
    for target in targets {
        match &target.source {
            FetchSource::Registry {
                registry_url,
                tarball_url,
            } if registry_source_is_public_npm_package(
                &target.name,
                &target.version,
                registry_url,
                tarball_url,
                client,
            ) =>
            {
                packages.push(NpmFirewallMaterializationPackage::new(
                    &target.name,
                    &target.version,
                    Some(&target.integrity),
                    None,
                ));
            }
            FetchSource::RemoteTarball { url }
                if is_canonical_public_npm_tarball(&target.name, &target.version, url) =>
            {
                packages.push(NpmFirewallMaterializationPackage::new(
                    &target.name,
                    &target.version,
                    Some(&target.integrity),
                    None,
                ));
            }
            _ => {}
        }
    }
    packages
}

fn registry_source_is_public_npm_package(
    name: &str,
    version: &str,
    registry_url: &str,
    tarball_url: &str,
    client: &RegistryClient,
) -> bool {
    if lpm_common::package_name::is_lpm_package(name) {
        return false;
    }
    crate::npm_public_source::is_public_npm_origin(registry_url)
        || crate::npm_public_source::is_lpm_registry_origin(registry_url, client)
        || (registry_url == "legacy" && is_canonical_public_npm_tarball(name, version, tarball_url))
}

fn is_canonical_public_npm_tarball(name: &str, version: &str, url: &str) -> bool {
    if lpm_common::package_name::is_lpm_package(name)
        || !crate::npm_public_source::is_public_npm_origin(url)
    {
        return false;
    }

    let Ok(parsed) = reqwest::Url::parse(url.trim()) else {
        return false;
    };
    if parsed.query().is_some() {
        return false;
    }

    let filename_name = name.rsplit('/').next().unwrap_or(name);
    let expected_file = format!("{filename_name}-{version}.tgz");
    let expected_plain_path = format!("{name}/-/{expected_file}");
    let expected_encoded_path = format!("{}/-/{}", npm_package_path_encoded(name), expected_file);
    let path = parsed.path().trim_start_matches('/');

    path == expected_plain_path || path.eq_ignore_ascii_case(&expected_encoded_path)
}

fn npm_package_path_encoded(name: &str) -> String {
    let mut encoded = String::with_capacity(name.len());
    for byte in name.bytes() {
        match byte {
            b'@' => encoded.push_str("%40"),
            b'/' => encoded.push_str("%2F"),
            _ => encoded.push(byte as char),
        }
    }
    encoded
}

fn result_for(target: &FetchTarget, status: FetchPackageStatus) -> FetchPackageResult {
    FetchPackageResult {
        name: target.name.clone(),
        version: target.version.clone(),
        source: target.source.label().to_string(),
        status,
        reason: None,
    }
}

fn count_results(results: &[FetchPackageResult]) -> FetchCounts {
    let mut counts = FetchCounts {
        total: results.len(),
        ..FetchCounts::default()
    };
    for result in results {
        match result.status {
            FetchPackageStatus::Fetched => counts.fetched += 1,
            FetchPackageStatus::Cached => counts.cached += 1,
            FetchPackageStatus::Skipped => counts.skipped += 1,
        }
    }
    counts
}

fn source_label(package: &LockedPackage) -> String {
    match package.source_kind() {
        Some(Ok(Source::Registry { .. })) | None => "registry".to_string(),
        Some(Ok(Source::Tarball { url })) if is_remote_tarball_url(&url) => {
            "remote_tarball".to_string()
        }
        Some(Ok(Source::Tarball { .. })) => "local_tarball".to_string(),
        Some(Ok(Source::Directory { .. })) | Some(Ok(Source::Link { .. })) => {
            "local_source".to_string()
        }
        Some(Ok(Source::Git { .. })) => "git".to_string(),
        Some(Err(_)) => "invalid".to_string(),
    }
}

fn is_remote_tarball_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://")
}

fn max_concurrent_downloads() -> usize {
    let Some(raw) = std::env::var("LPM_CONCURRENT_DOWNLOADS").ok() else {
        return DEFAULT_MAX_CONCURRENT_DOWNLOADS;
    };

    match raw.parse::<usize>() {
        Ok(value) if value > 0 && value <= 256 => value,
        _ => {
            crate::output::warn(&format!(
                "LPM_CONCURRENT_DOWNLOADS={raw:?} is not a valid integer in 1..=256 \
                 - falling back to default ({DEFAULT_MAX_CONCURRENT_DOWNLOADS})"
            ));
            DEFAULT_MAX_CONCURRENT_DOWNLOADS
        }
    }
}

fn package_matches_platform(package: &LockedPackage, platform: &FetchPlatform) -> bool {
    check_platform_filter(&package.os, &platform.os)
        && check_platform_filter(&package.cpu, &platform.cpu)
        && if package.libc.is_empty() {
            true
        } else {
            platform
                .libc
                .as_deref()
                .is_some_and(|libc| check_platform_filter(&package.libc, libc))
        }
}

fn check_platform_filter(entries: &[String], current: &str) -> bool {
    if entries.is_empty() {
        return true;
    }

    if entries.iter().any(|entry| entry.starts_with('!')) {
        entries.iter().all(|entry| {
            entry
                .strip_prefix('!')
                .is_none_or(|excluded| excluded != current)
        })
    } else {
        entries.iter().any(|entry| entry == current)
    }
}

fn render_platform(platform: &FetchPlatform) -> String {
    match platform.libc.as_deref() {
        Some(libc) => format!("{}/{}/{}", platform.os, platform.cpu, libc),
        None => format!("{}/{}", platform.os, platform.cpu),
    }
}

impl FetchPlatform {
    fn current() -> Self {
        Self {
            os: if cfg!(target_os = "macos") {
                "darwin"
            } else if cfg!(target_os = "linux") {
                "linux"
            } else if cfg!(target_os = "windows") {
                "win32"
            } else if cfg!(target_os = "freebsd") {
                "freebsd"
            } else {
                "unknown"
            }
            .to_string(),
            cpu: if cfg!(target_arch = "x86_64") {
                "x64"
            } else if cfg!(target_arch = "aarch64") {
                "arm64"
            } else if cfg!(target_arch = "x86") {
                "ia32"
            } else if cfg!(target_arch = "arm") {
                "arm"
            } else {
                "unknown"
            }
            .to_string(),
            libc: lpm_common::platform::detect_libc().map(str::to_string),
        }
    }

    fn parse(raw: &str) -> Result<Self, LpmError> {
        let parts = raw.split('/').collect::<Vec<_>>();
        if !(parts.len() == 2 || parts.len() == 3)
            || parts.iter().any(|part| part.trim().is_empty())
        {
            return Err(LpmError::Script(format!(
                "invalid --platform {raw:?}; expected os/arch or os/arch/libc, for example linux/x64/glibc"
            )));
        }

        let os = normalize_os(parts[0]);
        let cpu = normalize_cpu(parts[1]);
        let libc = (parts.len() == 3).then(|| parts[2].trim().to_ascii_lowercase());

        Ok(Self { os, cpu, libc })
    }
}

fn normalize_os(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "macos" | "mac" | "osx" => "darwin".to_string(),
        "windows" | "win" => "win32".to_string(),
        other => other.to_string(),
    }
}

fn normalize_cpu(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "amd64" | "x86_64" => "x64".to_string(),
        "aarch64" => "arm64".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked_package() -> LockedPackage {
        LockedPackage {
            instance_id: None,
            dependency_targets: std::collections::BTreeMap::new(),
            peer_targets: std::collections::BTreeMap::new(),
            name: "pkg".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-test".to_string()),
            manifest_fingerprint: None,
            registry_signatures: Vec::new(),
            registry_published_at: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            node_engine: None,
            optional: false,
            dependencies: Vec::new(),
            alias_dependencies: Vec::new(),
            peers: Vec::new(),
            peer_edges: Vec::new(),
            tarball: Some("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz".to_string()),
        }
    }

    #[test]
    fn platform_parser_normalizes_common_aliases() {
        let platform = FetchPlatform::parse("macos/aarch64").unwrap();
        assert_eq!(platform.os, "darwin");
        assert_eq!(platform.cpu, "arm64");
        assert_eq!(platform.libc, None);

        let linux = FetchPlatform::parse("linux/amd64/musl").unwrap();
        assert_eq!(linux.os, "linux");
        assert_eq!(linux.cpu, "x64");
        assert_eq!(linux.libc.as_deref(), Some("musl"));
    }

    #[test]
    fn platform_matching_uses_npm_include_and_exclude_semantics() {
        let mut package = locked_package();
        package.os = vec!["linux".to_string()];
        package.cpu = vec!["!ia32".to_string()];
        package.libc = vec!["musl".to_string()];

        assert!(package_matches_platform(
            &package,
            &FetchPlatform::parse("linux/x64/musl").unwrap()
        ));
        assert!(!package_matches_platform(
            &package,
            &FetchPlatform::parse("darwin/x64").unwrap()
        ));
        assert!(!package_matches_platform(
            &package,
            &FetchPlatform::parse("linux/x64/glibc").unwrap()
        ));
        assert!(!package_matches_platform(
            &package,
            &FetchPlatform::parse("linux/ia32/musl").unwrap()
        ));
    }

    #[test]
    fn registry_package_requires_integrity_and_tarball_url() {
        let mut package = locked_package();
        package.integrity = None;
        let err = classify_package(&package, &FetchPlatform::parse("linux/x64/glibc").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("missing integrity"));

        let mut package = locked_package();
        package.tarball = None;
        let err = classify_package(&package, &FetchPlatform::parse("linux/x64/glibc").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("missing tarball URL"));
    }

    #[test]
    fn canonical_public_npm_tarball_matches_unscoped_package_url() {
        assert!(is_canonical_public_npm_tarball(
            "ms",
            "2.1.3",
            "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"
        ));
    }

    #[test]
    fn canonical_public_npm_tarball_matches_scoped_package_url() {
        assert!(is_canonical_public_npm_tarball(
            "@scope/pkg",
            "1.2.3",
            "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz"
        ));
    }

    #[test]
    fn canonical_public_npm_tarball_rejects_mismatched_version() {
        assert!(!is_canonical_public_npm_tarball(
            "ms",
            "2.1.3",
            "https://registry.npmjs.org/ms/-/ms-2.1.4.tgz"
        ));
    }

    #[test]
    fn fetch_targets_include_canonical_public_npm_tarballs_in_firewall_preflight() {
        let targets = vec![FetchTarget {
            name: "ms".to_string(),
            version: "2.1.3".to_string(),
            integrity: "sha512-test".to_string(),
            source: FetchSource::RemoteTarball {
                url: "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz".to_string(),
            },
        }];
        let client = RegistryClient::new();

        let packages = npm_firewall_packages_for_fetch_targets(&targets, &client);

        assert_eq!(packages.len(), 1);
    }

    #[test]
    fn v2_store_for_fetch_uses_persisted_integrity_policy() {
        let _env =
            crate::test_env::ScopedEnv::update([(lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None)]);
        let root_dir = tempfile::tempdir().unwrap();
        let lpm_root = LpmRoot::from_dir(root_dir.path());
        let mut table = toml::map::Map::new();
        table.insert(
            "integrity".to_string(),
            toml::Value::String("tree".to_string()),
        );
        let global_config = crate::commands::config::GlobalConfig::from_table(table);

        let store =
            configured_v2_store_for_fetch(&lpm_root, &global_config, lpm_store::StoreVersion::V2)
                .unwrap();

        assert_eq!(
            store.object_integrity_policy(),
            lpm_store::v2::ObjectIntegrityPolicy::Tree
        );
    }

    #[test]
    fn classify_package_keeps_canonical_public_npm_tarball_as_remote_target() {
        let mut package = locked_package();
        package.name = "ms".to_string();
        package.version = "2.1.3".to_string();
        package.source = Some("tarball+https://registry.npmjs.org/ms/-/ms-2.1.3.tgz".to_string());
        package.tarball = None;

        let FetchPlan::Fetch(target) =
            classify_package(&package, &FetchPlatform::parse("linux/x64/glibc").unwrap()).unwrap()
        else {
            panic!("canonical public npm tarball must be fetched");
        };

        assert_eq!(
            target.source.url(),
            "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"
        );
    }
}
