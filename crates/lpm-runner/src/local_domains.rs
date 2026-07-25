//! Local-domain route planning for the dev proxy.

use crate::lpm_json::LpmJsonConfig;
use lpm_common::LocalTarget;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDomainRoute {
    /// Hostname requested by `lpm.json`.
    pub host: String,
    /// Verified loopback endpoint owned by the child service.
    pub upstream: LocalTarget,
    /// Service name for multi-service routes; `None` for single-script `lpm dev`.
    pub service: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalDomainRoutePlan {
    /// Reverse-proxy routes to register.
    pub routes: Vec<LocalDomainRoute>,
    /// Hostnames that need leaf certificate SAN coverage.
    pub extra_hostnames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsFilePlan {
    pub path: PathBuf,
    pub backup_path: PathBuf,
    pub block_id: String,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsFileCleanPlan {
    pub path: PathBuf,
    pub backup_path: PathBuf,
    pub block_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsFileCleanOutcome {
    pub path: PathBuf,
    pub backup_path: PathBuf,
    pub removed_blocks: usize,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedHostsFile {
    path: PathBuf,
    backup_path: PathBuf,
    block_id: String,
    changed: bool,
}

impl ManagedHostsFile {
    pub fn from_plan(plan: &HostsFilePlan, changed: bool) -> Self {
        Self {
            path: plan.path.clone(),
            backup_path: plan.backup_path.clone(),
            block_id: plan.block_id.clone(),
            changed,
        }
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn block_id(&self) -> &str {
        &self.block_id
    }

    pub fn release(self) -> Result<bool, String> {
        remove_managed_hosts_file_block(&self.path, &self.backup_path, &self.block_id)
    }
}

/// Return configured local-domain hosts in deterministic route-planning order.
pub fn configured_hostnames(config: &LpmJsonConfig) -> Vec<String> {
    let mut hosts = Vec::new();

    let mut service_names: Vec<&String> = config.services.keys().collect();
    service_names.sort();
    for service_name in service_names {
        if let Some(host) = config.services[service_name].host.as_ref() {
            hosts.push(host.clone());
        }
    }
    if let Some(proxy_host) = config.proxy.as_ref().and_then(|proxy| proxy.host.as_ref()) {
        hosts.push(proxy_host.clone());
    }

    dedupe_hostnames(hosts)
}

pub fn plan_hosts_file_update(
    project_dir: &Path,
    hostnames: &[String],
) -> Result<Option<HostsFilePlan>, String> {
    let hosts = hostnames_requiring_hosts_file(hostnames);
    if hosts.is_empty() {
        return Ok(None);
    }

    Ok(Some(HostsFilePlan {
        path: hosts_file_path(),
        backup_path: hosts_backup_path()?,
        block_id: managed_hosts_block_id(project_dir),
        hosts,
    }))
}

pub fn hostnames_requiring_hosts_file(hostnames: &[String]) -> Vec<String> {
    dedupe_hostnames(
        hostnames
            .iter()
            .filter(|host| requires_hosts_file_entry(host))
            .cloned(),
    )
}

pub fn requires_hosts_file_entry(host: &str) -> bool {
    !host.eq_ignore_ascii_case("localhost") && !host.to_ascii_lowercase().ends_with(".localhost")
}

pub fn apply_hosts_file_plan(plan: &HostsFilePlan) -> Result<ManagedHostsFile, String> {
    let changed = upsert_managed_hosts_file_block(
        &plan.path,
        &plan.backup_path,
        &plan.block_id,
        &plan.hosts,
    )?;
    Ok(ManagedHostsFile::from_plan(plan, changed))
}

pub fn ensure_hosts_file_backup(path: &Path, backup_path: &Path) -> Result<(), String> {
    backup_hosts_file_once(path, backup_path)
}

pub fn apply_hosts_file_plan_without_backup(
    plan: &HostsFilePlan,
) -> Result<ManagedHostsFile, String> {
    let changed =
        upsert_managed_hosts_file_block_without_backup(&plan.path, &plan.block_id, &plan.hosts)?;
    Ok(ManagedHostsFile::from_plan(plan, changed))
}

pub fn remove_hosts_file_block_without_backup(path: &Path, block_id: &str) -> Result<bool, String> {
    remove_managed_hosts_file_block_without_backup(path, block_id)
}

pub fn clean_hosts_file_without_backup(path: &Path) -> Result<HostsFileCleanOutcome, String> {
    let current = read_hosts_file(path)?;
    let (next, removed_blocks) = remove_all_managed_hosts_blocks(&current)?;
    if current == next {
        return Ok(HostsFileCleanOutcome {
            path: path.to_path_buf(),
            backup_path: PathBuf::new(),
            removed_blocks,
            changed: false,
        });
    }

    write_hosts_file_atomic(path, &next)?;
    Ok(HostsFileCleanOutcome {
        path: path.to_path_buf(),
        backup_path: PathBuf::new(),
        removed_blocks,
        changed: true,
    })
}

pub fn plan_hosts_file_clean() -> Result<HostsFileCleanPlan, String> {
    let path = hosts_file_path();
    let backup_path = hosts_backup_path()?;
    let current = read_hosts_file(&path)?;
    let (_, block_count) = remove_all_managed_hosts_blocks(&current)?;
    Ok(HostsFileCleanPlan {
        path,
        backup_path,
        block_count,
    })
}

pub fn apply_hosts_file_clean_plan(
    plan: &HostsFileCleanPlan,
) -> Result<HostsFileCleanOutcome, String> {
    let current = read_hosts_file(&plan.path)?;
    let (next, removed_blocks) = remove_all_managed_hosts_blocks(&current)?;
    if current == next {
        return Ok(HostsFileCleanOutcome {
            path: plan.path.clone(),
            backup_path: plan.backup_path.clone(),
            removed_blocks,
            changed: false,
        });
    }

    backup_hosts_file_once(&plan.path, &plan.backup_path)?;
    write_hosts_file_atomic(&plan.path, &next)?;
    Ok(HostsFileCleanOutcome {
        path: plan.path.clone(),
        backup_path: plan.backup_path.clone(),
        removed_blocks,
        changed: true,
    })
}

fn hosts_file_path() -> PathBuf {
    if let Ok(path) = std::env::var("LPM_HOSTS_FILE")
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }

    system_hosts_file_path()
}

pub fn system_hosts_file_path() -> PathBuf {
    #[cfg(windows)]
    {
        windows_hosts_file_path()
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

#[cfg(windows)]
fn windows_hosts_file_path() -> PathBuf {
    windows_system_directory()
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join(r"System32\drivers\etc\hosts")
}

#[cfg(windows)]
fn windows_system_directory() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    let mut buffer = vec![0u16; 260];
    loop {
        // SAFETY: `buffer` is valid writable UTF-16 storage and its length is
        // passed exactly as the Win32 API expects.
        let len = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if len == 0 {
            return None;
        }
        let len = len as usize;
        if len < buffer.len() {
            buffer.truncate(len);
            return Some(PathBuf::from(OsString::from_wide(&buffer)));
        }
        buffer.resize(len + 1, 0);
    }
}

fn managed_hosts_block_id(project_dir: &Path) -> String {
    format!(
        "project-{}",
        crate::dlx::deterministic_hash(&project_dir.to_string_lossy())
    )
}

fn hosts_backup_path() -> Result<PathBuf, String> {
    let root = lpm_common::LpmRoot::from_env()
        .map_err(|err| format!("resolve LPM root for hosts backup: {err}"))?;
    Ok(root.root().join("hosts.bak"))
}

fn upsert_managed_hosts_file_block(
    path: &Path,
    backup_path: &Path,
    block_id: &str,
    hosts: &[String],
) -> Result<bool, String> {
    let current = read_hosts_file(path)?;
    let next = upsert_managed_hosts_block(&current, block_id, hosts);
    if current == next {
        return Ok(false);
    }
    backup_hosts_file_once(path, backup_path)?;
    write_hosts_file_atomic(path, &next)?;
    Ok(true)
}

fn upsert_managed_hosts_file_block_without_backup(
    path: &Path,
    block_id: &str,
    hosts: &[String],
) -> Result<bool, String> {
    let current = read_hosts_file(path)?;
    let next = upsert_managed_hosts_block(&current, block_id, hosts);
    if current == next {
        return Ok(false);
    }
    write_hosts_file_atomic(path, &next)?;
    Ok(true)
}

fn remove_managed_hosts_file_block(
    path: &Path,
    backup_path: &Path,
    block_id: &str,
) -> Result<bool, String> {
    let current = read_hosts_file(path)?;
    let next = remove_managed_hosts_block(&current, block_id);
    if current == next {
        return Ok(false);
    }
    backup_hosts_file_once(path, backup_path)?;
    write_hosts_file_atomic(path, &next)?;
    Ok(true)
}

fn remove_managed_hosts_file_block_without_backup(
    path: &Path,
    block_id: &str,
) -> Result<bool, String> {
    let current = read_hosts_file(path)?;
    let next = remove_managed_hosts_block(&current, block_id);
    if current == next {
        return Ok(false);
    }
    write_hosts_file_atomic(path, &next)?;
    Ok(true)
}

fn read_hosts_file(path: &Path) -> Result<String, String> {
    match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok(content) => Ok(content),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => Ok(String::new()),
        Err(err) => Err(format!("read hosts file {}: {err}", path.display())),
    }
}

fn backup_hosts_file_once(path: &Path, backup_path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    if backup_path.exists() {
        return Ok(());
    }
    if let Some(parent) = backup_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    std::fs::copy(path, backup_path).map_err(|err| {
        format!(
            "backup hosts file {} to {}: {err}",
            path.display(),
            backup_path.display()
        )
    })?;
    Ok(())
}

fn write_hosts_file_atomic(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create hosts file directory {}: {err}", parent.display()))?;
    }

    lpm_common::write_file_atomic(path, content)
        .map_err(|err| format!("replace hosts file {}: {err}", path.display()))
}

fn upsert_managed_hosts_block(content: &str, block_id: &str, hosts: &[String]) -> String {
    let newline = preferred_newline(content);
    let without_existing = remove_managed_hosts_block_with_newline(content, block_id, newline);
    let block = render_managed_hosts_block(block_id, hosts, newline);
    let trimmed = without_existing.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        block
    } else {
        format!("{trimmed}{newline}{newline}{block}")
    }
}

fn remove_managed_hosts_block(content: &str, block_id: &str) -> String {
    remove_managed_hosts_block_with_newline(content, block_id, preferred_newline(content))
}

fn remove_all_managed_hosts_blocks(content: &str) -> Result<(String, usize), String> {
    remove_all_managed_hosts_blocks_with_newline(content, preferred_newline(content))
}

fn remove_managed_hosts_block_with_newline(content: &str, block_id: &str, newline: &str) -> String {
    let begin = managed_hosts_begin(block_id);
    let end = managed_hosts_end(block_id);
    let mut out: Vec<&str> = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        if line == begin {
            if out.last().is_some_and(|previous| previous.is_empty()) {
                out.pop();
            }
            in_block = true;
            continue;
        }
        if in_block {
            if line == end {
                in_block = false;
            }
            continue;
        }
        out.push(line);
    }
    let mut rendered = out.join(newline);
    if !rendered.is_empty() {
        rendered.push_str(newline);
    }
    rendered
}

fn remove_all_managed_hosts_blocks_with_newline(
    content: &str,
    newline: &str,
) -> Result<(String, usize), String> {
    let mut out: Vec<&str> = Vec::new();
    let mut in_block = None::<String>;
    let mut removed = 0usize;

    for line in content.lines() {
        if let Some(block_id) = in_block.as_deref() {
            if line == managed_hosts_end(block_id) {
                in_block = None;
            }
            continue;
        }

        if let Some(block_id) = parse_managed_hosts_begin(line) {
            if out.last().is_some_and(|previous| previous.is_empty()) {
                out.pop();
            }
            in_block = Some(block_id.to_string());
            removed += 1;
            continue;
        }

        out.push(line);
    }

    if let Some(block_id) = in_block {
        return Err(format!(
            "hosts file contains unterminated LPM managed block `{block_id}`"
        ));
    }

    let mut rendered = out.join(newline);
    if !rendered.is_empty() {
        rendered.push_str(newline);
    }
    Ok((rendered, removed))
}

fn render_managed_hosts_block(block_id: &str, hosts: &[String], newline: &str) -> String {
    let hosts = dedupe_hostnames(hosts.iter().cloned());
    let mut out = String::new();
    out.push_str(&managed_hosts_begin(block_id));
    out.push_str(newline);
    for host in hosts {
        out.push_str("127.0.0.1 ");
        out.push_str(&host);
        out.push_str(newline);
    }
    out.push_str(&managed_hosts_end(block_id));
    out.push_str(newline);
    out
}

fn preferred_newline(content: &str) -> &'static str {
    if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

fn managed_hosts_begin(block_id: &str) -> String {
    format!("# >>> lpm:{block_id} >>>")
}

fn managed_hosts_end(block_id: &str) -> String {
    format!("# <<< lpm:{block_id} <<<")
}

fn parse_managed_hosts_begin(line: &str) -> Option<&str> {
    let block_id = line
        .strip_prefix("# >>> lpm:")?
        .strip_suffix(" >>>")?
        .trim();
    (!block_id.is_empty()).then_some(block_id)
}

/// Build route registrations for `lpm.json` services using verified child endpoints.
pub fn plan_multi_service_routes(
    config: &LpmJsonConfig,
    final_targets: &HashMap<String, LocalTarget>,
) -> Result<LocalDomainRoutePlan, String> {
    let mut routes = Vec::new();

    let mut service_names: Vec<&String> = config.services.keys().collect();
    service_names.sort();
    for service_name in service_names {
        let service = &config.services[service_name];
        let Some(host) = service.host.as_ref() else {
            continue;
        };
        let Some(upstream) = final_targets.get(service_name) else {
            return Err(format!(
                "service `{service_name}` declares host `{host}` but has no verified child endpoint"
            ));
        };
        routes.push(LocalDomainRoute {
            host: host.clone(),
            upstream: upstream.clone(),
            service: Some(service_name.clone()),
        });
    }

    if let Some(proxy_host) = config.proxy.as_ref().and_then(|proxy| proxy.host.as_ref()) {
        let service_name = primary_proxy_service(config)?;
        let Some(upstream) = final_targets.get(service_name) else {
            return Err(format!(
                "proxy.host `{proxy_host}` targets service `{service_name}` but that service has no verified child endpoint"
            ));
        };
        routes.push(LocalDomainRoute {
            host: proxy_host.clone(),
            upstream: upstream.clone(),
            service: Some(service_name.to_string()),
        });
    }

    Ok(LocalDomainRoutePlan {
        extra_hostnames: route_hostnames(&routes),
        routes,
    })
}

/// Build the top-level proxy route for single-script `lpm dev`.
pub fn plan_single_service_route(
    config: &LpmJsonConfig,
    upstream: LocalTarget,
) -> Option<LocalDomainRoutePlan> {
    let proxy_host = config.proxy.as_ref()?.host.as_ref()?;
    let routes = vec![LocalDomainRoute {
        host: proxy_host.clone(),
        upstream,
        service: None,
    }];
    Some(LocalDomainRoutePlan {
        extra_hostnames: route_hostnames(&routes),
        routes,
    })
}

fn primary_proxy_service(config: &LpmJsonConfig) -> Result<&str, String> {
    if config.services.is_empty() {
        return Err("proxy.host requires a service target".to_string());
    }

    let mut primary = config
        .services
        .iter()
        .filter(|(_, service)| service.primary)
        .map(|(name, _)| name.as_str());
    if let Some(name) = primary.next() {
        if primary.next().is_some() {
            return Err("proxy.host requires exactly one primary service".to_string());
        }
        return Ok(name);
    }

    if config.services.len() == 1 {
        return config
            .services
            .keys()
            .next()
            .map(|name| name.as_str())
            .ok_or_else(|| "proxy.host requires a service target".to_string());
    }

    Err("proxy.host with multiple services requires one service marked primary".to_string())
}

fn route_hostnames(routes: &[LocalDomainRoute]) -> Vec<String> {
    dedupe_hostnames(routes.iter().map(|route| route.host.clone()))
}

fn dedupe_hostnames(hosts: impl IntoIterator<Item = String>) -> Vec<String> {
    let iterator = hosts.into_iter();
    let (lower, _) = iterator.size_hint();
    let mut seen = HashSet::with_capacity(lower);
    let mut hostnames = Vec::with_capacity(lower);
    for host in iterator {
        if seen.insert(host.clone()) {
            hostnames.push(host);
        }
    }
    hostnames
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpm_json::{LpmJsonConfig, ProxyConfig, ServiceConfig};

    #[test]
    fn plan_multi_service_routes_preserves_the_verified_child_endpoint() {
        let config = LpmJsonConfig {
            services: HashMap::from([(
                "web".to_string(),
                ServiceConfig {
                    command: "next dev".to_string(),
                    port: Some(3000),
                    host: Some("web.app.localhost".to_string()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let upstream =
            LocalTarget::loopback(lpm_common::LocalScheme::Http, 3001).with_base_path("/app/");
        let final_targets = HashMap::from([("web".to_string(), upstream.clone())]);

        let plan = plan_multi_service_routes(&config, &final_targets).unwrap();

        assert_eq!(
            plan.routes,
            vec![LocalDomainRoute {
                host: "web.app.localhost".to_string(),
                upstream,
                service: Some("web".to_string()),
            }]
        );
        assert_eq!(plan.extra_hostnames, vec!["web.app.localhost"]);
    }

    #[test]
    fn plan_multi_service_routes_errors_when_host_service_has_no_verified_endpoint() {
        let config = LpmJsonConfig {
            services: HashMap::from([(
                "web".to_string(),
                ServiceConfig {
                    command: "next dev".to_string(),
                    port: Some(3000),
                    host: Some("web.app.localhost".to_string()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let err = plan_multi_service_routes(&config, &HashMap::new()).unwrap_err();

        assert!(err.contains("web"), "got {err}");
        assert!(err.contains("verified child endpoint"), "got {err}");
    }

    #[test]
    fn plan_multi_service_routes_maps_proxy_host_to_primary_service() {
        let config = LpmJsonConfig {
            proxy: Some(ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            services: HashMap::from([
                (
                    "api".to_string(),
                    ServiceConfig {
                        command: "node api.js".to_string(),
                        port: Some(4000),
                        ..Default::default()
                    },
                ),
                (
                    "web".to_string(),
                    ServiceConfig {
                        command: "next dev".to_string(),
                        port: Some(3000),
                        primary: true,
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        let web_target = LocalTarget::loopback(lpm_common::LocalScheme::Http, 3001);
        let final_targets = HashMap::from([
            ("web".to_string(), web_target.clone()),
            (
                "api".to_string(),
                LocalTarget::loopback(lpm_common::LocalScheme::Http, 4000),
            ),
        ]);

        let plan = plan_multi_service_routes(&config, &final_targets).unwrap();

        assert_eq!(
            plan.routes,
            vec![LocalDomainRoute {
                host: "app.localhost".to_string(),
                upstream: web_target,
                service: Some("web".to_string()),
            }]
        );
    }

    #[test]
    fn plan_multi_service_routes_rejects_ambiguous_proxy_host_target() {
        let config = LpmJsonConfig {
            proxy: Some(ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            services: HashMap::from([
                (
                    "api".to_string(),
                    ServiceConfig {
                        command: "node api.js".to_string(),
                        port: Some(4000),
                        ..Default::default()
                    },
                ),
                (
                    "web".to_string(),
                    ServiceConfig {
                        command: "next dev".to_string(),
                        port: Some(3000),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        let err = plan_multi_service_routes(&config, &HashMap::new()).unwrap_err();

        assert!(err.contains("primary"), "got {err}");
    }

    #[test]
    fn plan_multi_service_routes_rejects_proxy_host_without_services() {
        let config = LpmJsonConfig {
            proxy: Some(ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = plan_multi_service_routes(&config, &HashMap::new()).unwrap_err();

        assert!(err.contains("service target"), "got {err}");
    }

    #[test]
    fn plan_single_service_route_uses_proxy_host() {
        let config = LpmJsonConfig {
            proxy: Some(ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let upstream = LocalTarget::loopback(lpm_common::LocalScheme::Http, 5173);
        let plan = plan_single_service_route(&config, upstream.clone()).unwrap();

        assert_eq!(
            plan.routes,
            vec![LocalDomainRoute {
                host: "app.localhost".to_string(),
                upstream,
                service: None,
            }]
        );
        assert_eq!(plan.extra_hostnames, vec!["app.localhost"]);
    }

    #[test]
    fn configured_hostnames_returns_services_then_proxy_without_duplicates() {
        let config = LpmJsonConfig {
            proxy: Some(ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            services: HashMap::from([
                (
                    "web".to_string(),
                    ServiceConfig {
                        command: "next dev".to_string(),
                        port: Some(3000),
                        host: Some("app.localhost".to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "api".to_string(),
                    ServiceConfig {
                        command: "node api.js".to_string(),
                        port: Some(4000),
                        host: Some("api.localhost".to_string()),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        assert_eq!(
            configured_hostnames(&config),
            vec!["api.localhost", "app.localhost"]
        );
    }

    #[test]
    fn hostnames_requiring_hosts_file_skips_localhost_tld_only() {
        let hosts = vec![
            "app.localhost".to_string(),
            "api.test".to_string(),
            "api.test".to_string(),
            "db.home.arpa".to_string(),
        ];

        assert_eq!(
            hostnames_requiring_hosts_file(&hosts),
            vec!["api.test", "db.home.arpa"]
        );
    }

    #[test]
    fn upsert_managed_hosts_block_replaces_existing_project_block() {
        let content = "127.0.0.1 localhost\n\n# >>> lpm:project-abc >>>\n127.0.0.1 old.test\n# <<< lpm:project-abc <<<\n\n10.0.0.1 router\n";

        let next = upsert_managed_hosts_block(
            content,
            "project-abc",
            &["api.test".to_string(), "web.test".to_string()],
        );

        assert!(!next.contains("old.test"));
        assert!(next.contains("127.0.0.1 localhost"));
        assert!(next.contains("10.0.0.1 router"));
        assert!(next.contains("# >>> lpm:project-abc >>>"));
        assert!(next.contains("127.0.0.1 api.test"));
        assert!(next.contains("127.0.0.1 web.test"));
        assert!(next.contains("# <<< lpm:project-abc <<<"));
    }

    #[test]
    fn remove_managed_hosts_block_preserves_unmanaged_lines() {
        let content = "127.0.0.1 localhost\n# >>> lpm:project-abc >>>\n127.0.0.1 api.test\n# <<< lpm:project-abc <<<\n10.0.0.1 router\n";

        let next = remove_managed_hosts_block(content, "project-abc");

        assert_eq!(next, "127.0.0.1 localhost\n10.0.0.1 router\n");
    }

    #[test]
    fn remove_all_managed_hosts_blocks_preserves_unmanaged_lines() {
        let content = "127.0.0.1 localhost\n\n# >>> lpm:project-abc >>>\n127.0.0.1 api.test\n# <<< lpm:project-abc <<<\n\n10.0.0.1 router\n# >>> lpm:project-def >>>\n127.0.0.1 web.test\n# <<< lpm:project-def <<<\n";

        let (next, removed) = remove_all_managed_hosts_blocks(content).unwrap();

        assert_eq!(removed, 2);
        assert_eq!(next, "127.0.0.1 localhost\n\n10.0.0.1 router\n");
    }

    #[test]
    fn remove_all_managed_hosts_blocks_rejects_unterminated_lpm_block() {
        let content = "127.0.0.1 localhost\n# >>> lpm:project-abc >>>\n127.0.0.1 api.test\n";

        let err = remove_all_managed_hosts_blocks(content).unwrap_err();

        assert!(err.contains("unterminated LPM managed block"), "got {err}");
    }

    #[test]
    fn upsert_managed_hosts_block_preserves_crlf_hosts_file_style() {
        let content = "127.0.0.1 localhost\r\n";

        let next = upsert_managed_hosts_block(content, "project-abc", &["api.test".to_string()]);

        assert!(next.contains("127.0.0.1 localhost\r\n\r\n"));
        assert!(next.contains("# >>> lpm:project-abc >>>\r\n"));
        assert!(next.contains("127.0.0.1 api.test\r\n"));
        assert!(next.ends_with("# <<< lpm:project-abc <<<\r\n"));
    }

    #[test]
    fn apply_hosts_file_plan_writes_and_release_removes_project_block() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let backup_path = dir.path().join("hosts.bak");
        std::fs::write(&hosts_path, "127.0.0.1 localhost\n").unwrap();
        let plan = HostsFilePlan {
            path: hosts_path.clone(),
            backup_path: backup_path.clone(),
            block_id: "project-abc".to_string(),
            hosts: vec!["api.test".to_string()],
        };

        let lease = apply_hosts_file_plan(&plan).unwrap();
        assert!(lease.changed());
        let content = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(content.contains("127.0.0.1 api.test"));

        assert!(lease.release().unwrap());
        let content = std::fs::read_to_string(&hosts_path).unwrap();
        assert_eq!(content, "127.0.0.1 localhost\n");
        let backup = std::fs::read_to_string(&backup_path).unwrap();
        assert_eq!(backup, "127.0.0.1 localhost\n");
    }

    #[test]
    fn apply_hosts_file_plan_without_backup_writes_only_target_file() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let backup_path = dir.path().join("hosts.bak");
        std::fs::write(&hosts_path, "127.0.0.1 localhost\n").unwrap();
        let plan = HostsFilePlan {
            path: hosts_path.clone(),
            backup_path: backup_path.clone(),
            block_id: "project-abc".to_string(),
            hosts: vec!["api.test".to_string()],
        };

        let lease = apply_hosts_file_plan_without_backup(&plan).unwrap();

        assert!(lease.changed());
        let content = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(content.contains("127.0.0.1 api.test"));
        assert!(!backup_path.exists());
    }

    #[test]
    fn remove_hosts_file_block_without_backup_removes_target_block_only() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let content = "127.0.0.1 localhost\n# >>> lpm:project-abc >>>\n127.0.0.1 api.test\n# <<< lpm:project-abc <<<\n";
        std::fs::write(&hosts_path, content).unwrap();

        let changed = remove_hosts_file_block_without_backup(&hosts_path, "project-abc").unwrap();

        assert!(changed);
        assert_eq!(
            std::fs::read_to_string(&hosts_path).unwrap(),
            "127.0.0.1 localhost\n"
        );
    }

    #[test]
    fn apply_hosts_file_clean_plan_removes_all_lpm_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let backup_path = dir.path().join("hosts.bak");
        let original = "127.0.0.1 localhost\n# >>> lpm:project-abc >>>\n127.0.0.1 api.test\n# <<< lpm:project-abc <<<\n10.0.0.1 router\n# >>> lpm:project-def >>>\n127.0.0.1 web.test\n# <<< lpm:project-def <<<\n";
        std::fs::write(&hosts_path, original).unwrap();
        let plan = HostsFileCleanPlan {
            path: hosts_path.clone(),
            backup_path: backup_path.clone(),
            block_count: 2,
        };

        let outcome = apply_hosts_file_clean_plan(&plan).unwrap();

        assert!(outcome.changed);
        assert_eq!(outcome.removed_blocks, 2);
        let content = std::fs::read_to_string(&hosts_path).unwrap();
        assert_eq!(content, "127.0.0.1 localhost\n10.0.0.1 router\n");
        let backup = std::fs::read_to_string(&backup_path).unwrap();
        assert_eq!(backup, original);
    }

    #[test]
    fn clean_hosts_file_without_backup_removes_blocks_without_creating_backup() {
        let dir = tempfile::tempdir().unwrap();
        let hosts_path = dir.path().join("hosts");
        let backup_path = dir.path().join("hosts.bak");
        let original = "127.0.0.1 localhost\n# >>> lpm:project-abc >>>\n127.0.0.1 api.test\n# <<< lpm:project-abc <<<\n";
        std::fs::write(&hosts_path, original).unwrap();

        let outcome = clean_hosts_file_without_backup(&hosts_path).unwrap();

        assert!(outcome.changed);
        assert_eq!(outcome.removed_blocks, 1);
        assert_eq!(
            std::fs::read_to_string(&hosts_path).unwrap(),
            "127.0.0.1 localhost\n"
        );
        assert!(!backup_path.exists());
    }
}
