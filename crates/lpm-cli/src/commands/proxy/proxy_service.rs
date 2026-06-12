use super::listener_args;
use super::proxy_platform::{
    install_privileged_forwarder_platform, install_proxy_service_platform,
    uninstall_privileged_forwarder_platform, uninstall_proxy_service_platform,
};
use super::resolve_start_options;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::paths::LpmRoot;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

pub(super) fn run_install(
    project_dir: &Path,
    json_output: bool,
    privileged_ports: bool,
    replace: bool,
    http_port: Option<u16>,
    http_redirect_port: Option<u16>,
    tls_port: Option<u16>,
) -> Result<(), LpmError> {
    let requested_options =
        resolve_start_options(project_dir, http_port, http_redirect_port, tls_port)?;
    let listener_flags_explicit =
        http_port.is_some() || http_redirect_port.is_some() || tls_port.is_some();
    let plan = ProxyServicePlan::new(
        project_dir,
        requested_options,
        privileged_ports,
        listener_flags_explicit,
        replace,
    )?;

    if proxy_service_dry_run() {
        print_service_json("install", false, true, &plan);
        return Ok(());
    }

    install_proxy_service_platform(&plan.user_service)?;
    if let Some(forwarder) = &plan.privileged_forwarder {
        install_privileged_forwarder_platform(forwarder)?;
    }
    if json_output {
        print_service_json("install", true, false, &plan);
    } else {
        install_ui::done("local proxy service installed");
        if plan.privileged_forwarder.is_some() {
            install_ui::done("privileged local-domain forwarder installed");
        } else {
            install_ui::warn(
                "the service is user-scoped; use `lpm proxy install --privileged-ports` for Unix 80/443 forwarding",
            );
        }
    }
    Ok(())
}

pub(super) fn run_uninstall(json_output: bool, privileged_ports: bool) -> Result<(), LpmError> {
    let plan = ProxyServicePlan::uninstall(privileged_ports)?;
    if proxy_service_dry_run() {
        print_service_json("uninstall", false, true, &plan);
        return Ok(());
    }

    if let Some(forwarder) = &plan.privileged_forwarder {
        uninstall_privileged_forwarder_platform(forwarder).map_err(|err| {
            LpmError::Script(format_privileged_forwarder_cleanup_error(&err, forwarder))
        })?;
    }
    uninstall_proxy_service_platform(&plan.user_service)?;
    if json_output {
        print_service_json("uninstall", true, false, &plan);
    } else {
        install_ui::done("local proxy service removed");
        if plan.privileged_forwarder.is_some() {
            install_ui::done("privileged local-domain forwarder removed");
        }
    }
    Ok(())
}

pub(super) fn format_privileged_forwarder_cleanup_error(
    err: &LpmError,
    forwarder: &PrivilegedForwarderSpec,
) -> String {
    format!(
        "{err}; privileged forwarder artifacts may remain at {} and {}",
        forwarder.service_path.display(),
        forwarder.config_path.display()
    )
}

#[derive(Debug, Clone)]
struct ProxyServicePlan {
    user_service: ProxyServiceSpec,
    privileged_forwarder: Option<PrivilegedForwarderSpec>,
}

impl ProxyServicePlan {
    fn new(
        project_dir: &Path,
        requested_options: lpm_proxy::ProxyDaemonOptions,
        privileged_ports: bool,
        listener_flags_explicit: bool,
        replace_existing: bool,
    ) -> Result<Self, LpmError> {
        if !privileged_ports {
            reject_privileged_user_service_ports(requested_options)?;
            return Ok(Self {
                user_service: ProxyServiceSpec::new(project_dir, requested_options)?,
                privileged_forwarder: None,
            });
        }

        let forwarder = PrivilegedForwarderSpec::new(
            requested_options,
            listener_flags_explicit,
            replace_existing,
        )?;
        let user_service = ProxyServiceSpec::new(project_dir, forwarder.backend_options)?;
        Ok(Self {
            user_service,
            privileged_forwarder: Some(forwarder),
        })
    }

    fn uninstall(privileged_ports: bool) -> Result<Self, LpmError> {
        let user_service =
            ProxyServiceSpec::new(Path::new("."), lpm_proxy::ProxyDaemonOptions::default())?;
        let privileged_forwarder = privileged_ports
            .then(PrivilegedForwarderSpec::for_uninstall)
            .transpose()?;
        Ok(Self {
            user_service,
            privileged_forwarder,
        })
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(windows, allow(dead_code))]
pub(super) struct ProxyServiceSpec {
    pub(super) label: &'static str,
    pub(super) exe: PathBuf,
    pub(super) working_dir: PathBuf,
    pub(super) lpm_home: PathBuf,
    pub(super) start_args: Vec<String>,
    pub(super) launcher_path: PathBuf,
    pub(super) stdout_log: PathBuf,
    pub(super) stderr_log: PathBuf,
}

impl ProxyServiceSpec {
    fn new(project_dir: &Path, options: lpm_proxy::ProxyDaemonOptions) -> Result<Self, LpmError> {
        let root = LpmRoot::from_env()?;
        let lpm_home = root.root().to_path_buf();
        let service_dir = lpm_home.join("services").join("proxy");
        let mut start_args = Vec::with_capacity(2 + 6);
        start_args.push("proxy".to_string());
        start_args.push("start".to_string());
        start_args.extend(listener_args(options));
        let launcher_name = if cfg!(windows) {
            "start-proxy.cmd"
        } else {
            "start-proxy.sh"
        };
        Ok(Self {
            label: "dev.lpm.proxy",
            exe: std::env::current_exe().map_err(LpmError::Io)?,
            working_dir: project_dir.to_path_buf(),
            lpm_home,
            start_args,
            launcher_path: service_dir.join(launcher_name),
            stdout_log: service_dir.join("proxy.out.log"),
            stderr_log: service_dir.join("proxy.err.log"),
        })
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(windows, allow(dead_code))]
pub(super) struct PrivilegedForwarderSpec {
    pub(super) label: &'static str,
    pub(super) exe: PathBuf,
    pub(super) start_args: Vec<String>,
    pub(super) config_path: PathBuf,
    pub(super) service_path: PathBuf,
    pub(super) stdout_log: PathBuf,
    pub(super) stderr_log: PathBuf,
    pub(super) backend_options: lpm_proxy::ProxyDaemonOptions,
    pub(super) config: PrivilegedForwarderConfig,
    pub(super) replace_existing: bool,
}

impl PrivilegedForwarderSpec {
    fn new(
        requested_options: lpm_proxy::ProxyDaemonOptions,
        listener_flags_explicit: bool,
        replace_existing: bool,
    ) -> Result<Self, LpmError> {
        #[cfg(not(unix))]
        {
            let _ = requested_options;
            let _ = listener_flags_explicit;
            let _ = replace_existing;
            return Err(LpmError::Script(
                "`--privileged-ports` is only supported on Unix platforms".into(),
            ));
        }

        #[cfg(unix)]
        {
            #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
            {
                let _ = requested_options;
                let _ = listener_flags_explicit;
                let _ = replace_existing;
                return Err(LpmError::Script(
                    "`--privileged-ports` is only supported on Linux and macOS".into(),
                ));
            }

            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let external_options =
                    privileged_external_options(requested_options, listener_flags_explicit)?;
                validate_privileged_external_options(external_options)?;
                let target_uid = current_effective_uid();
                if target_uid == 0 {
                    return Err(LpmError::Script(
                    "`lpm proxy install --privileged-ports` must be run as the target user, not with sudo"
                        .into(),
                ));
                }
                let root = LpmRoot::from_env()?;
                let config_path = privileged_forwarder_config_path();
                reject_conflicting_privileged_forwarder_owner(
                    &config_path,
                    target_uid,
                    replace_existing,
                )?;
                let backend_options = privileged_backend_options(external_options)?;
                let service_path = privileged_forwarder_service_path("dev.lpm.proxy.forwarder");
                let stdout_log = privileged_forwarder_stdout_log();
                let stderr_log = privileged_forwarder_stderr_log();
                let start_args = vec![
                    "proxy".to_string(),
                    "forwarder".to_string(),
                    "--forwarder-config".to_string(),
                    config_path.display().to_string(),
                ];
                let exe = std::env::current_exe().map_err(LpmError::Io)?;
                let config = PrivilegedForwarderConfig::new(
                    target_uid,
                    root.proxy_state(),
                    exe.clone(),
                    external_options,
                    backend_options,
                )?;
                Ok(Self {
                    label: "dev.lpm.proxy.forwarder",
                    exe,
                    start_args,
                    config_path,
                    service_path,
                    stdout_log,
                    stderr_log,
                    backend_options,
                    config,
                    replace_existing,
                })
            }
        }
    }

    fn for_uninstall() -> Result<Self, LpmError> {
        #[cfg(not(unix))]
        {
            return Err(LpmError::Script(
                "`--privileged-ports` is only supported on Unix platforms".into(),
            ));
        }

        #[cfg(unix)]
        {
            #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
            {
                return Err(LpmError::Script(
                    "`--privileged-ports` is only supported on Linux and macOS".into(),
                ));
            }

            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let root = LpmRoot::from_env()?;
                let config_path = privileged_forwarder_config_path();
                let service_path = privileged_forwarder_service_path("dev.lpm.proxy.forwarder");
                let start_args = vec![
                    "proxy".to_string(),
                    "forwarder".to_string(),
                    "--forwarder-config".to_string(),
                    config_path.display().to_string(),
                ];
                Ok(Self {
                    label: "dev.lpm.proxy.forwarder",
                    exe: std::env::current_exe().map_err(LpmError::Io)?,
                    start_args,
                    config_path,
                    service_path,
                    stdout_log: privileged_forwarder_stdout_log(),
                    stderr_log: privileged_forwarder_stderr_log(),
                    backend_options: lpm_proxy::ProxyDaemonOptions::default(),
                    config: PrivilegedForwarderConfig {
                        target_uid: current_effective_uid(),
                        state_path: root.proxy_state(),
                        binary_path: std::env::current_exe().map_err(LpmError::Io)?,
                        rules: Vec::new(),
                    },
                    replace_existing: false,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PrivilegedForwarderConfig {
    pub(super) target_uid: u32,
    pub(super) state_path: PathBuf,
    pub(super) binary_path: PathBuf,
    pub(super) rules: Vec<PrivilegedForwarderRuleConfig>,
}

impl PrivilegedForwarderConfig {
    #[cfg_attr(windows, allow(dead_code))]
    pub(super) fn new(
        target_uid: u32,
        state_path: PathBuf,
        binary_path: PathBuf,
        external_options: lpm_proxy::ProxyDaemonOptions,
        backend_options: lpm_proxy::ProxyDaemonOptions,
    ) -> Result<Self, LpmError> {
        let mut rules = Vec::with_capacity(2);
        if let (Some(external_port), Some(backend_port)) =
            (external_options.tls_port, backend_options.tls_port)
        {
            rules.push(PrivilegedForwarderRuleConfig::new(
                "https",
                external_port,
                backend_port,
            ));
        }
        if let (Some(external_port), Some(backend_port)) = (
            external_options.http_redirect_port,
            backend_options.http_redirect_port,
        ) {
            rules.push(PrivilegedForwarderRuleConfig::new(
                "httpRedirect",
                external_port,
                backend_port,
            ));
        }
        if rules.is_empty() {
            return Err(LpmError::Script(
                "`--privileged-ports` requires at least one low-port HTTPS or redirect listener"
                    .into(),
            ));
        }
        Ok(Self {
            target_uid,
            state_path,
            binary_path,
            rules,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PrivilegedForwarderRuleConfig {
    pub(super) name: String,
    pub(super) listen_addr: SocketAddr,
    pub(super) target_addr: SocketAddr,
}

impl PrivilegedForwarderRuleConfig {
    #[cfg_attr(windows, allow(dead_code))]
    pub(super) fn new(name: &str, listen_port: u16, target_port: u16) -> Self {
        Self {
            name: name.to_string(),
            listen_addr: loopback_socket_addr(listen_port),
            target_addr: loopback_socket_addr(target_port),
        }
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub(super) fn privileged_external_options(
    requested_options: lpm_proxy::ProxyDaemonOptions,
    listener_flags_explicit: bool,
) -> Result<lpm_proxy::ProxyDaemonOptions, LpmError> {
    if requested_options.http_port.is_some() {
        return Err(LpmError::Script(
            "`--privileged-ports` supports HTTPS plus HTTP redirect only; plain `--http-port` is not forwarded in v1"
                .into(),
        ));
    }
    if !listener_flags_explicit {
        if requested_options.tls_port.is_none() && requested_options.http_redirect_port.is_none() {
            return Ok(lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(80),
                tls_port: Some(443),
            });
        }
        return Ok(lpm_proxy::ProxyDaemonOptions {
            http_port: None,
            http_redirect_port: requested_options.http_redirect_port.map(|_| 80),
            tls_port: requested_options.tls_port.map(|_| 443),
        });
    }
    if requested_options.tls_port.is_none() && requested_options.http_redirect_port.is_none() {
        return Ok(lpm_proxy::ProxyDaemonOptions {
            http_port: None,
            http_redirect_port: Some(80),
            tls_port: Some(443),
        });
    }
    Ok(requested_options)
}

#[cfg_attr(windows, allow(dead_code))]
pub(super) fn validate_privileged_external_options(
    options: lpm_proxy::ProxyDaemonOptions,
) -> Result<(), LpmError> {
    if options.http_redirect_port.is_some() && options.tls_port.is_none() {
        return Err(LpmError::Script(
            "`--privileged-ports` HTTP redirect forwarding requires an HTTPS listener".into(),
        ));
    }
    let mut privileged_ports = Vec::with_capacity(2);
    if let Some(port) = options.tls_port {
        privileged_ports.push(("HTTPS", port));
    }
    if let Some(port) = options.http_redirect_port {
        privileged_ports.push(("HTTP redirect", port));
    }
    for (label, port) in privileged_ports {
        if !(1..1024).contains(&port) {
            return Err(LpmError::Script(format!(
                "`--privileged-ports` expects low external listener ports; {label} port {port} does not need the Unix forwarder"
            )));
        }
    }
    Ok(())
}

#[cfg_attr(windows, allow(dead_code))]
fn privileged_backend_options(
    external_options: lpm_proxy::ProxyDaemonOptions,
) -> Result<lpm_proxy::ProxyDaemonOptions, LpmError> {
    let mut reserved = Vec::with_capacity(2);
    let tls_port = if external_options.tls_port.is_some() {
        Some(find_available_backend_port(9443, &mut reserved)?)
    } else {
        None
    };
    let http_redirect_port = if external_options.http_redirect_port.is_some() {
        Some(find_available_backend_port(9080, &mut reserved)?)
    } else {
        None
    };
    Ok(lpm_proxy::ProxyDaemonOptions {
        http_port: None,
        http_redirect_port,
        tls_port,
    })
}

#[cfg_attr(windows, allow(dead_code))]
fn find_available_backend_port(start: u16, reserved: &mut Vec<u16>) -> Result<u16, LpmError> {
    for port in start..=u16::MAX {
        if reserved.contains(&port) {
            continue;
        }
        if matches!(
            lpm_runner::ports::check_port(port),
            lpm_runner::ports::PortStatus::Free
        ) {
            reserved.push(port);
            return Ok(port);
        }
    }
    Err(LpmError::Script(format!(
        "could not find an available proxy backend port at or above {start}"
    )))
}

#[cfg_attr(windows, allow(dead_code))]
pub(super) fn reject_conflicting_privileged_forwarder_owner(
    config_path: &Path,
    target_uid: u32,
    replace_existing: bool,
) -> Result<(), LpmError> {
    match read_existing_privileged_forwarder_config(config_path)? {
        Some(config) if config.target_uid != target_uid && !replace_existing => {
            Err(LpmError::Script(format!(
                "privileged proxy forwarder is already owned by UID {}; refusing to replace it for UID {target_uid}. Re-run `lpm proxy install --privileged-ports --replace` to intentionally replace it, or delete {} with administrator approval.",
                config.target_uid,
                config_path.display()
            )))
        }
        _ => Ok(()),
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub(super) fn reject_removing_foreign_privileged_forwarder(
    config_path: &Path,
    target_uid: u32,
) -> Result<(), LpmError> {
    match read_existing_privileged_forwarder_config(config_path)? {
        Some(config) if config.target_uid != target_uid => Err(LpmError::Script(format!(
            "privileged proxy forwarder is owned by UID {}; refusing to remove it as UID {target_uid}",
            config.target_uid
        ))),
        _ => Ok(()),
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn read_existing_privileged_forwarder_config(
    config_path: &Path,
) -> Result<Option<PrivilegedForwarderConfig>, LpmError> {
    let bytes = match std::fs::read(config_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(LpmError::Script(format!(
                "read existing privileged proxy forwarder config {}: {err}",
                config_path.display()
            )));
        }
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|err| {
        LpmError::Script(format!(
            "parse existing privileged proxy forwarder config {}: {err}",
            config_path.display()
        ))
    })
}

#[cfg_attr(windows, allow(dead_code))]
pub(super) fn loopback_socket_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[cfg(unix)]
pub(super) fn current_effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() as u32 }
}

#[cfg(target_os = "linux")]
fn privileged_forwarder_config_path() -> PathBuf {
    PathBuf::from("/etc/lpm/proxy-forwarder.json")
}

#[cfg(target_os = "macos")]
fn privileged_forwarder_config_path() -> PathBuf {
    PathBuf::from("/Library/Application Support/LPM/proxy-forwarder.json")
}

#[cfg(target_os = "linux")]
fn privileged_forwarder_service_path(label: &str) -> PathBuf {
    PathBuf::from("/etc/systemd/system").join(super::proxy_platform::linux_systemd_unit_name(label))
}

#[cfg(target_os = "macos")]
fn privileged_forwarder_service_path(label: &str) -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(format!("{label}.plist"))
}

#[cfg(unix)]
fn privileged_forwarder_stdout_log() -> PathBuf {
    PathBuf::from("/var/log/lpm-proxy-forwarder.out.log")
}

#[cfg(unix)]
fn privileged_forwarder_stderr_log() -> PathBuf {
    PathBuf::from("/var/log/lpm-proxy-forwarder.err.log")
}

pub(super) fn reject_privileged_user_service_ports(
    options: lpm_proxy::ProxyDaemonOptions,
) -> Result<(), LpmError> {
    #[cfg(unix)]
    {
        let privileged = [
            options.http_port,
            options.http_redirect_port,
            options.tls_port,
        ]
        .into_iter()
        .flatten()
        .filter(|port| (1..1024).contains(port))
        .collect::<Vec<_>>();
        if !privileged.is_empty() {
            return Err(LpmError::Script(format!(
                "`lpm proxy install` installs a user-scoped service and cannot bind privileged ports {}. Use `lpm proxy install --privileged-ports` for Unix 80/443 forwarding, or set `proxy.port` to a high port such as 9443.",
                privileged
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    let _ = options;
    Ok(())
}

fn proxy_service_dry_run() -> bool {
    matches!(
        std::env::var("LPM_PROXY_SERVICE_DRY_RUN").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Ok("on")
    )
}

fn print_service_json(action: &str, changed: bool, dry_run: bool, plan: &ProxyServicePlan) {
    let forwarder = plan
        .privileged_forwarder
        .as_ref()
        .map(privileged_forwarder_json);
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "action": action,
            "changed": changed,
            "dryRun": dry_run,
            "service": plan.user_service.label,
            "launcher": plan.user_service.launcher_path,
            "args": plan.user_service.start_args,
            "privilegedForwarder": forwarder,
        })
    );
}

fn privileged_forwarder_json(spec: &PrivilegedForwarderSpec) -> serde_json::Value {
    serde_json::json!({
        "service": spec.label,
        "servicePath": spec.service_path,
        "configPath": spec.config_path,
        "args": spec.start_args,
        "targetUid": spec.config.target_uid,
        "statePath": spec.config.state_path,
        "rules": spec.config.rules,
    })
}
