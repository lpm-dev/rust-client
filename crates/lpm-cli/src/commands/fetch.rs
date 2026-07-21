use crate::commands::install::{
    NpmFirewallMaterializationPackage, prepare_npm_firewall_materialization_preflight,
    run_prepared_npm_firewall_materialization_preflight,
};
use crate::install_ui;
use lpm_common::{LpmError, LpmRoot};
use lpm_lockfile::{LockedPackage, Source};
use lpm_registry::RegistryClient;
use lpm_store::PackageStore;
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const DEFAULT_MAX_CONCURRENT_DOWNLOADS: usize = 24;

#[derive(Debug, Clone, Serialize)]
struct FetchPlatform {
    os: String,
    cpu: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    libc: Option<String>,
}

#[derive(Debug, Clone)]
enum FetchSource {
    Registry {
        registry_url: String,
        tarball_url: String,
    },
    RemoteTarball {
        url: String,
    },
}

impl FetchSource {
    fn url(&self) -> &str {
        match self {
            Self::Registry { tarball_url, .. } => tarball_url,
            Self::RemoteTarball { url } => url,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Registry { .. } => "registry",
            Self::RemoteTarball { .. } => "remote_tarball",
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
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if !lockfile_path.exists() {
        return Err(LpmError::NotFound(
            "no lpm.lock found. Run `lpm install` before `lpm fetch`.".into(),
        ));
    }

    let target_platform = match platform {
        Some(raw) => FetchPlatform::parse(raw)?,
        None => FetchPlatform::current(),
    };
    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path)
        .map_err(|e| LpmError::Registry(format!("failed to read lpm.lock: {e}")))?;

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

    let lpm_root = LpmRoot::from_env()?;
    let store = PackageStore::from_root(&lpm_root);
    let store_v2 = v2_store_for_fetch(&lpm_root)?;
    if store_v2.is_none() {
        validate_v1_target_identities(&targets)?;
    }

    let firewall_packages = npm_firewall_packages_for_fetch_targets(&targets, client);
    let firewall_preflight = prepare_npm_firewall_materialization_preflight(
        project_dir,
        &firewall_packages,
        json_output,
    )?;

    if !json_output {
        let fetch_message = format!(
            "Fetching {} package(s) from lpm.lock",
            install_ui::yellow(&targets.len().to_string())
        );
        install_ui::phase(&install_ui::with_firewall_badge(
            fetch_message,
            firewall_preflight.is_active(),
        ));
        install_ui::detail(&format!(
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

    let v2_enabled = store_v2.is_some();
    let fetches = fetch_targets_under_store_lock(
        Arc::new(client.clone_with_config()),
        Arc::new(store),
        store_v2,
        targets,
    );
    let mut fetched = if v2_enabled {
        lpm_common::with_shared_lock_async(lpm_root.store_lock(), fetches).await?
    } else {
        lpm_common::with_exclusive_lock_async(lpm_root.store_lock(), fetches).await?
    };
    results.append(&mut fetched);

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
            install_ui::skipped(&format!(
                "Skipped {} local/platform package(s)",
                counts.skipped
            ));
        }
        let elapsed = install_ui::format_duration(started.elapsed());
        install_ui::done(&format!(
            "Done · fetched {}, cached {}, skipped {} in {}",
            install_ui::green(&counts.fetched.to_string()),
            install_ui::green(&counts.cached.to_string()),
            install_ui::green(&counts.skipped.to_string()),
            install_ui::green(&elapsed)
        ));
    }

    Ok(())
}

async fn fetch_targets_under_store_lock(
    client: Arc<RegistryClient>,
    store: Arc<PackageStore>,
    store_v2: Option<Arc<lpm_store::v2::Store>>,
    targets: Vec<FetchTarget>,
) -> Result<Vec<FetchPackageResult>, LpmError> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent_downloads()));
    let mut tasks = JoinSet::new();
    for target in targets {
        let client = Arc::clone(&client);
        let store = Arc::clone(&store);
        let store_v2 = store_v2.clone();
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move { fetch_one(client, store, store_v2, semaphore, target).await });
    }

    let mut results = Vec::with_capacity(tasks.len());
    while let Some(joined) = tasks.join_next().await {
        results.push(
            joined
                .map_err(|e| LpmError::Registry(format!("fetch worker failed to join: {e}")))??,
        );
    }
    Ok(results)
}

fn validate_v1_target_identities(targets: &[FetchTarget]) -> Result<(), LpmError> {
    let mut identities = std::collections::HashMap::with_capacity(targets.len());
    for target in targets {
        let coordinates = (&target.name, &target.version);
        let source = match &target.source {
            FetchSource::Registry {
                registry_url,
                tarball_url,
            } => ("registry", registry_url.as_str(), tarball_url.as_str()),
            FetchSource::RemoteTarball { url } => ("remote_tarball", url.as_str(), url.as_str()),
        };
        let identity = (target.integrity.as_str(), source);
        if let Some(previous) = identities.insert(coordinates, identity)
            && previous != identity
        {
            return Err(LpmError::Store(format!(
                "lpm fetch cannot cache distinct source identities for {}@{} in store v1; use the default store v2 by unsetting LPM_STORE_VERSION",
                target.name, target.version
            )));
        }
    }
    Ok(())
}

fn v2_store_for_fetch(lpm_root: &LpmRoot) -> Result<Option<Arc<lpm_store::v2::Store>>, LpmError> {
    if !lpm_store::StoreVersion::from_env().is_v2() {
        return Ok(None);
    }
    let global_config = crate::commands::config::GlobalConfig::load_checked()?;
    Ok(Some(configured_v2_store_for_fetch(
        lpm_root,
        &global_config,
    )?))
}

fn configured_v2_store_for_fetch(
    lpm_root: &LpmRoot,
    global_config: &crate::commands::config::GlobalConfig,
) -> Result<Arc<lpm_store::v2::Store>, LpmError> {
    let object_integrity_policy =
        crate::commands::config::resolve_object_integrity_policy(global_config)?;
    Ok(Arc::new(
        lpm_store::v2::Store::from_lpm_root_with_object_integrity_policy(
            lpm_root,
            object_integrity_policy,
        ),
    ))
}

async fn fetch_one(
    client: Arc<RegistryClient>,
    store: Arc<PackageStore>,
    store_v2: Option<Arc<lpm_store::v2::Store>>,
    semaphore: Arc<Semaphore>,
    target: FetchTarget,
) -> Result<FetchPackageResult, LpmError> {
    if is_cached(&target, &store, store_v2.as_deref()) {
        return Ok(result_for(&target, FetchPackageStatus::Cached));
    }

    let permit = semaphore
        .acquire_owned()
        .await
        .map_err(|_| LpmError::Registry("download semaphore closed".into()))?;
    let (data, _computed_sri) = client
        .download_tarball_with_integrity(target.source.url(), Some(&target.integrity))
        .await?;
    drop(permit);

    let source = target.source.clone();
    let name = target.name.clone();
    let version = target.version.clone();
    let integrity = target.integrity.clone();
    tokio::task::spawn_blocking(move || -> Result<(), LpmError> {
        if let Some(store_v2) = store_v2 {
            store_v2.extract_object_from_bytes(&data, Some(&integrity))?;
            return Ok(());
        }

        match source {
            FetchSource::Registry { .. } => {
                store.store_package_with_integrity(&name, &version, &data, &integrity)?;
            }
            FetchSource::RemoteTarball { .. } => {
                store.store_tarball_at_cas_path(&integrity, &data)?;
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| LpmError::Registry(format!("fetch store worker failed to join: {e}")))??;

    Ok(result_for(&target, FetchPackageStatus::Fetched))
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
        Source::Git { url } => Err(LpmError::Registry(format!(
            "lpm fetch cannot materialize git source {url} from lpm.lock yet; use `lpm install` while online for this dependency"
        ))),
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
        FetchSource::Registry { .. } => {
            store.has_package_with_integrity(&target.name, &target.version, &target.integrity)
        }
        FetchSource::RemoteTarball { .. } => store.has_tarball(&target.integrity),
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
            name: "pkg".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-test".to_string()),
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
    fn v1_fetch_rejects_same_coordinates_with_distinct_source_identities() {
        let first = FetchTarget {
            name: "shared".into(),
            version: "1.0.0".into(),
            integrity: "sha512-first".into(),
            source: FetchSource::Registry {
                registry_url: "https://registry-a.example".into(),
                tarball_url: "https://registry-a.example/shared.tgz".into(),
            },
        };
        let second = FetchTarget {
            name: "shared".into(),
            version: "1.0.0".into(),
            integrity: "sha512-second".into(),
            source: FetchSource::Registry {
                registry_url: "https://registry-b.example".into(),
                tarball_url: "https://registry-b.example/shared.tgz".into(),
            },
        };

        let error = validate_v1_target_identities(&[first, second]).unwrap_err();

        assert!(error.to_string().contains("store v2"));
        assert!(error.to_string().contains("shared@1.0.0"));
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

        let store = configured_v2_store_for_fetch(&lpm_root, &global_config).unwrap();

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

    #[test]
    fn v1_registry_cache_hit_requires_the_lockfile_integrity() {
        let root = tempfile::tempdir().unwrap();
        let store = PackageStore::at(root.path());
        let cached_dir = store.package_dir("cached", "1.0.0");
        std::fs::create_dir_all(&cached_dir).unwrap();
        std::fs::write(
            cached_dir.join("package.json"),
            br#"{"name":"cached","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(cached_dir.join(".integrity"), "sha512-cached-source").unwrap();
        let target = FetchTarget {
            name: "cached".into(),
            version: "1.0.0".into(),
            integrity: "sha256-different-source".into(),
            source: FetchSource::Registry {
                registry_url: "https://registry.example".into(),
                tarball_url: "https://registry.example/cached.tgz".into(),
            },
        };

        assert!(
            !is_cached(&target, &store, None),
            "a coordinate-only v1 entry must not satisfy a different lockfile SRI"
        );
    }
}
