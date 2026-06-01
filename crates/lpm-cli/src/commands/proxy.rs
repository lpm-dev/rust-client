use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_common::paths::LpmRoot;
use lpm_proxy::ProxyStatus;
use lpm_runner::lpm_json;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) struct DetachedProxyStart {
    pub(crate) status: ProxyStatus,
    pub(crate) started: bool,
}

pub(crate) struct ProxyRunOptions<'a> {
    pub(crate) action: &'a str,
    pub(crate) project_dir: &'a Path,
    pub(crate) json_output: bool,
    pub(crate) detach: bool,
    pub(crate) privileged_ports: bool,
    pub(crate) replace: bool,
    pub(crate) http_port: Option<u16>,
    pub(crate) http_redirect_port: Option<u16>,
    pub(crate) tls_port: Option<u16>,
    pub(crate) forwarder_config: Option<&'a Path>,
}

/// Run the `lpm proxy` subcommand.
pub async fn run(options: ProxyRunOptions<'_>) -> Result<(), LpmError> {
    let ProxyRunOptions {
        action,
        project_dir,
        json_output,
        detach,
        privileged_ports,
        replace,
        http_port,
        http_redirect_port,
        tls_port,
        forwarder_config,
    } = options;
    if forwarder_config.is_some() && action != "forwarder" {
        return Err(LpmError::Script(
            "`--forwarder-config` is only valid for the internal proxy forwarder".into(),
        ));
    }
    if replace && !(action == "install" && privileged_ports) {
        return Err(LpmError::Script(
            "`--replace` is only valid with `lpm proxy install --privileged-ports`".into(),
        ));
    }
    if action == "forwarder" {
        return run_forwarder_action(
            json_output,
            detach,
            privileged_ports,
            http_port,
            http_redirect_port,
            tls_port,
            forwarder_config,
        )
        .await;
    }
    if detach && action != "start" {
        return Err(LpmError::Script(
            "`--detach` is only valid as `lpm proxy start --detach`".into(),
        ));
    }
    if privileged_ports && !matches!(action, "install" | "uninstall") {
        return Err(LpmError::Script(
            "`--privileged-ports` is only valid with `lpm proxy install` or `lpm proxy uninstall`"
                .into(),
        ));
    }
    if http_port.is_some() && !matches!(action, "start" | "install") {
        return Err(LpmError::Script(
            "`--http-port` is only valid with `lpm proxy start` or `lpm proxy install`".into(),
        ));
    }
    if http_redirect_port.is_some() && !matches!(action, "start" | "install") {
        return Err(LpmError::Script(
            "`--http-redirect-port` is only valid with `lpm proxy start` or `lpm proxy install`"
                .into(),
        ));
    }
    if http_redirect_port.is_some() && tls_port.is_none() {
        return Err(LpmError::Script(
            "`--http-redirect-port <port>` requires `--tls-port <port>`".into(),
        ));
    }
    if tls_port.is_some() && !matches!(action, "start" | "install") {
        return Err(LpmError::Script(
            "`--tls-port` is only valid with `lpm proxy start` or `lpm proxy install`".into(),
        ));
    }

    match action {
        "status" => run_status(json_output).await,
        "list" => run_list(json_output).await,
        "start" => {
            run_start(
                project_dir,
                json_output,
                detach,
                http_port,
                http_redirect_port,
                tls_port,
            )
            .await
        }
        "stop" => run_stop(json_output).await,
        "install" => run_install(
            project_dir,
            json_output,
            privileged_ports,
            replace,
            http_port,
            http_redirect_port,
            tls_port,
        ),
        "uninstall" => run_uninstall(json_output, privileged_ports),
        _ => Err(LpmError::Script(format!(
            "unknown proxy action '{action}'. Available: status, list, start, stop, install, uninstall"
        ))),
    }
}

async fn run_forwarder_action(
    json_output: bool,
    detach: bool,
    privileged_ports: bool,
    http_port: Option<u16>,
    http_redirect_port: Option<u16>,
    tls_port: Option<u16>,
    forwarder_config: Option<&Path>,
) -> Result<(), LpmError> {
    if json_output || detach || privileged_ports {
        return Err(LpmError::Script(
            "the internal proxy forwarder does not accept CLI output or service flags".into(),
        ));
    }
    if http_port.is_some() || http_redirect_port.is_some() || tls_port.is_some() {
        return Err(LpmError::Script(
            "the internal proxy forwarder reads listeners from `--forwarder-config`".into(),
        ));
    }
    let config_path = forwarder_config.ok_or_else(|| {
        LpmError::Script("the internal proxy forwarder requires `--forwarder-config <path>`".into())
    })?;
    run_forwarder(config_path).await
}

#[cfg(unix)]
async fn run_forwarder(config_path: &Path) -> Result<(), LpmError> {
    if current_effective_uid() != 0 {
        return Err(LpmError::Script(
            "the internal proxy forwarder must run as root".into(),
        ));
    }
    let bytes = std::fs::read(config_path).map_err(LpmError::Io)?;
    let config: PrivilegedForwarderConfig =
        serde_json::from_slice(&bytes).map_err(|err| LpmError::Script(err.to_string()))?;
    if config.rules.is_empty() {
        return Err(LpmError::Script(format!(
            "forwarder config {} has no rules",
            config_path.display()
        )));
    }

    let mut handles = Vec::with_capacity(config.rules.len());
    for rule_config in &config.rules {
        let rule =
            lpm_proxy::TcpForwarderRule::new(rule_config.listen_addr, rule_config.target_addr)
                .map_err(|err| LpmError::Script(err.to_string()))?;
        let guard = lpm_proxy::UnixForwarderGuard::new(
            config.state_path.clone(),
            config.target_uid,
            rule_config.target_addr,
        )
        .map_err(|err| LpmError::Script(err.to_string()))?;
        handles.push(
            lpm_proxy::start_guarded_tcp_forwarder(rule, guard)
                .await
                .map_err(|err| LpmError::Script(err.to_string()))?,
        );
    }

    let _handles = handles;
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(not(unix))]
async fn run_forwarder(_config_path: &Path) -> Result<(), LpmError> {
    Err(LpmError::Script(
        "the internal proxy forwarder is only supported on Unix platforms".into(),
    ))
}

async fn run_status(json_output: bool) -> Result<(), LpmError> {
    let status = read_status().await?;
    if json_output {
        print_status_json(&status);
        return Ok(());
    }

    render_status_human(&status);
    Ok(())
}

async fn run_list(json_output: bool) -> Result<(), LpmError> {
    let status = read_status().await?;
    if json_output {
        print_status_json(&status);
        return Ok(());
    }

    render_routes_human(&status);
    Ok(())
}

async fn run_start(
    project_dir: &Path,
    json_output: bool,
    detach: bool,
    http_port: Option<u16>,
    http_redirect_port: Option<u16>,
    tls_port: Option<u16>,
) -> Result<(), LpmError> {
    let options = resolve_start_options(project_dir, http_port, http_redirect_port, tls_port)?;
    if detach {
        return run_start_detached(project_dir, json_output, options).await;
    }
    if json_output {
        return Err(LpmError::Script(
            "`lpm proxy start --json` is not supported for foreground mode; use `lpm proxy status --json` from another shell"
            .into(),
        ));
    }

    let mut listeners = Vec::with_capacity(3);
    if let Some(port) = options.http_port {
        listeners.push(format!("HTTP on 127.0.0.1:{port}"));
    }
    if let Some(port) = options.http_redirect_port {
        listeners.push(format!("HTTP redirect on 127.0.0.1:{port}"));
    }
    if let Some(port) = options.tls_port {
        listeners.push(format!("HTTPS on 127.0.0.1:{port}"));
    }
    let message = if listeners.is_empty() {
        "Starting local proxy control daemon".to_string()
    } else {
        format!(
            "Starting local proxy control daemon with {}",
            listeners.join(", ")
        )
    };
    install_ui::phase(&message);
    lpm_proxy::serve_control_default_with_options(options)
        .await
        .map_err(|err| LpmError::Script(err.to_string()))?;
    install_ui::done("local proxy control daemon stopped");
    Ok(())
}

async fn run_start_detached(
    project_dir: &Path,
    json_output: bool,
    options: lpm_proxy::ProxyDaemonOptions,
) -> Result<(), LpmError> {
    let start = ensure_detached_started_with_options(project_dir, options).await?;
    if json_output {
        print_status_json(&start.status);
    } else if start.started {
        install_ui::done("local proxy control daemon started in the background");
    } else {
        install_ui::done("local proxy control daemon is already running");
    }
    Ok(())
}

pub(crate) async fn ensure_detached_started_for_project(
    project_dir: &Path,
) -> Result<DetachedProxyStart, LpmError> {
    let options = resolve_start_options(project_dir, None, None, None)?;
    ensure_detached_started_with_options(project_dir, options).await
}

async fn ensure_detached_started_with_options(
    project_dir: &Path,
    options: lpm_proxy::ProxyDaemonOptions,
) -> Result<DetachedProxyStart, LpmError> {
    let status = read_status().await?;
    if status.running {
        return Ok(DetachedProxyStart {
            status,
            started: false,
        });
    }

    let exe = std::env::current_exe().map_err(LpmError::Io)?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("proxy")
        .arg("start")
        .current_dir(project_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach_background_command(&mut command);
    append_listener_args(&mut command, options);
    prepare_detached_spawn_handles().map_err(|err| {
        LpmError::Script(format!(
            "failed to prepare detached proxy daemon handles: {err}"
        ))
    })?;
    let mut child = command
        .spawn()
        .map_err(|err| LpmError::Script(format!("failed to start detached proxy daemon: {err}")))?;

    let status = wait_for_detached_start(&mut child).await?;
    Ok(DetachedProxyStart {
        status,
        started: true,
    })
}

fn detach_background_command(command: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        // SAFETY: setsid() is async-signal-safe and has no preconditions
        // beyond being called in a child process (guaranteed by pre_exec).
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};

        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
}

fn append_listener_args(command: &mut Command, options: lpm_proxy::ProxyDaemonOptions) {
    command.args(listener_args(options));
}

fn prepare_detached_spawn_handles() -> std::io::Result<()> {
    #[cfg(windows)]
    {
        clear_standard_handle_inheritance()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(windows)]
fn clear_standard_handle_inheritance() -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    for handle_id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = unsafe {
            // SAFETY: `handle_id` is one of the documented standard-handle
            // constants accepted by GetStdHandle.
            GetStdHandle(handle_id)
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        let ok = unsafe {
            // SAFETY: `handle` is a process-owned standard handle. Clearing
            // only the inherit flag does not close or replace it.
            SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn listener_args(options: lpm_proxy::ProxyDaemonOptions) -> Vec<String> {
    let mut args = Vec::with_capacity(6);
    if let Some(port) = options.http_port {
        args.push("--http-port".to_string());
        args.push(port.to_string());
    }
    if let Some(port) = options.tls_port {
        args.push("--tls-port".to_string());
        args.push(port.to_string());
    }
    if let Some(port) = options.http_redirect_port {
        args.push("--http-redirect-port".to_string());
        args.push(port.to_string());
    }
    args
}

async fn wait_for_detached_start(child: &mut std::process::Child) -> Result<ProxyStatus, LpmError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(LpmError::Io)? {
            return Err(LpmError::Script(format!(
                "detached proxy daemon exited before becoming ready ({status}); run `lpm proxy start` in the foreground for details"
            )));
        }
        match read_status().await {
            Ok(status) if status.running => return Ok(status),
            Ok(_) | Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.kill();
    Err(LpmError::Script(
        "detached proxy daemon did not become ready within 10s".into(),
    ))
}

fn resolve_start_options(
    project_dir: &Path,
    http_port: Option<u16>,
    http_redirect_port: Option<u16>,
    tls_port: Option<u16>,
) -> Result<lpm_proxy::ProxyDaemonOptions, LpmError> {
    if http_port.is_some() || http_redirect_port.is_some() || tls_port.is_some() {
        return Ok(lpm_proxy::ProxyDaemonOptions {
            http_port,
            http_redirect_port,
            tls_port,
        });
    }

    let Some(config) = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)? else {
        return Ok(lpm_proxy::ProxyDaemonOptions::default());
    };
    if lpm_runner::local_domains::configured_hostnames(&config).is_empty() {
        return Ok(lpm_proxy::ProxyDaemonOptions::default());
    }

    let proxy = config.proxy.as_ref();
    let tls_port = Some(proxy.and_then(|proxy| proxy.port).unwrap_or(443));
    let http_redirect_port = proxy
        .and_then(|proxy| proxy.http_redirect)
        .unwrap_or(true)
        .then_some(80);

    Ok(lpm_proxy::ProxyDaemonOptions {
        http_port: None,
        http_redirect_port,
        tls_port,
    })
}

async fn run_stop(json_output: bool) -> Result<(), LpmError> {
    let stopped = match lpm_proxy::send_request(lpm_proxy::ProxyRequest::Stop).await {
        Ok(lpm_proxy::ProxyResponse::Stopped) => true,
        Ok(lpm_proxy::ProxyResponse::Error { message }) => {
            return Err(LpmError::Script(message));
        }
        Ok(other) => {
            return Err(LpmError::Script(format!(
                "unexpected proxy stop response: {other:?}"
            )));
        }
        Err(lpm_proxy::ProxyError::IpcUnavailable(_))
        | Err(lpm_proxy::ProxyError::IpcUnsupported) => false,
        Err(err) => return Err(LpmError::Script(err.to_string())),
    };

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "stopped": stopped,
            })
        );
    } else if stopped {
        install_ui::done("local proxy control daemon stopped");
    } else {
        install_ui::warn("local proxy control daemon is not running");
    }
    Ok(())
}

async fn read_status() -> Result<ProxyStatus, LpmError> {
    lpm_proxy::status()
        .await
        .map_err(|err| LpmError::Script(err.to_string()))
}

fn print_status_json(status: &ProxyStatus) {
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "running": status.running,
            "pid": status.pid,
            "httpAddr": status.http_addr,
            "httpRedirectAddr": status.http_redirect_addr,
            "tlsAddr": status.tls_addr,
            "routes": status.routes,
            "stale": status.stale,
            "stateError": status.state_error,
        })
    );
}

fn render_status_human(status: &ProxyStatus) {
    eprintln!("{}", install_ui::section("Local proxy"));
    if status.running {
        let pid = status
            .pid
            .map_or_else(|| "PID unknown".to_string(), |pid| format!("PID {pid}"));
        print_field(
            "status",
            &format!("{} ({pid})", install_ui::status_ok("running")),
        );
        if let Some(http_addr) = &status.http_addr {
            print_field("http", &install_ui::url(http_addr));
        }
        if let Some(http_redirect_addr) = &status.http_redirect_addr {
            print_field("redirect", &install_ui::url(http_redirect_addr));
        }
        if let Some(tls_addr) = &status.tls_addr {
            print_field("https", &install_ui::url(tls_addr));
        }
    } else {
        print_field("status", &install_ui::dim("not running"));
    }

    if status.stale {
        install_ui::warn("stale proxy state found; no routes are active");
        if let Some(error) = &status.state_error {
            eprintln!("  {}", install_ui::dim(error));
        }
    }

    eprintln!();
    render_routes_human(status);
}

fn render_routes_human(status: &ProxyStatus) {
    if status.routes.is_empty() {
        install_ui::warn("No proxy routes");
        return;
    }

    let host_width = status
        .routes
        .iter()
        .map(|route| route.host.len())
        .chain(std::iter::once("Host".len()))
        .max()
        .unwrap_or("Host".len());
    let project_width = status
        .routes
        .iter()
        .map(|route| route.project_dir.display().to_string().len())
        .chain(std::iter::once("Project".len()))
        .max()
        .unwrap_or("Project".len());

    eprintln!(
        "{}  {}  {}  {}",
        install_ui::dim(&format!("{:<host_width$}", "Host")),
        install_ui::dim("Port"),
        install_ui::dim(&format!("{:<project_width$}", "Project")),
        install_ui::dim("Service"),
    );
    for route in &status.routes {
        let project = route.project_dir.display().to_string();
        let service = route.service.as_deref().unwrap_or("-");
        eprintln!(
            "{}  {}  {}  {}",
            format!("{:<host_width$}", route.host).yellow(),
            route.upstream_port.to_string().green(),
            format!("{project:<project_width$}").dimmed(),
            service,
        );
    }
}

fn print_field(label: &str, value: &str) {
    eprintln!("  {} {}", install_ui::dim(&format!("{label:<10}")), value);
}

fn run_install(
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

fn run_uninstall(json_output: bool, privileged_ports: bool) -> Result<(), LpmError> {
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

fn format_privileged_forwarder_cleanup_error(
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
struct ProxyServiceSpec {
    label: &'static str,
    exe: PathBuf,
    working_dir: PathBuf,
    lpm_home: PathBuf,
    start_args: Vec<String>,
    launcher_path: PathBuf,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
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
struct PrivilegedForwarderSpec {
    label: &'static str,
    exe: PathBuf,
    start_args: Vec<String>,
    config_path: PathBuf,
    service_path: PathBuf,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
    backend_options: lpm_proxy::ProxyDaemonOptions,
    config: PrivilegedForwarderConfig,
    replace_existing: bool,
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
struct PrivilegedForwarderConfig {
    target_uid: u32,
    state_path: PathBuf,
    binary_path: PathBuf,
    rules: Vec<PrivilegedForwarderRuleConfig>,
}

impl PrivilegedForwarderConfig {
    #[cfg_attr(windows, allow(dead_code))]
    fn new(
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
struct PrivilegedForwarderRuleConfig {
    name: String,
    listen_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl PrivilegedForwarderRuleConfig {
    #[cfg_attr(windows, allow(dead_code))]
    fn new(name: &str, listen_port: u16, target_port: u16) -> Self {
        Self {
            name: name.to_string(),
            listen_addr: loopback_socket_addr(listen_port),
            target_addr: loopback_socket_addr(target_port),
        }
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn privileged_external_options(
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
fn validate_privileged_external_options(
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
fn reject_conflicting_privileged_forwarder_owner(
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
fn reject_removing_foreign_privileged_forwarder(
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
fn loopback_socket_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[cfg(unix)]
fn current_effective_uid() -> u32 {
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
    PathBuf::from("/etc/systemd/system").join(linux_systemd_unit_name(label))
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

fn reject_privileged_user_service_ports(
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

#[cfg(target_os = "macos")]
fn install_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    let plist_path = macos_launch_agent_path(spec.label)?;
    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }
    if let Some(parent) = spec.stdout_log.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }
    std::fs::write(&plist_path, render_macos_launch_agent_plist(spec)).map_err(LpmError::Io)?;

    let target = macos_launchctl_target(spec.label);
    let _ = Command::new("launchctl")
        .args(["bootout", &target])
        .status();
    run_checked(
        Command::new("launchctl")
            .arg("bootstrap")
            .arg(macos_gui_domain())
            .arg(&plist_path),
    )?;
    run_checked(Command::new("launchctl").args(["enable", &target]))?;
    run_checked(Command::new("launchctl").args(["kickstart", "-k", &target]))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    let target = macos_launchctl_target(spec.label);
    let _ = Command::new("launchctl")
        .args(["bootout", &target])
        .status();
    let plist_path = macos_launch_agent_path(spec.label)?;
    if plist_path.exists() {
        std::fs::remove_file(plist_path).map_err(LpmError::Io)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    write_unix_launcher(spec)?;
    let unit_path = linux_systemd_user_unit_path(spec.label)?;
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }
    std::fs::write(&unit_path, render_linux_systemd_unit(spec)).map_err(LpmError::Io)?;
    let unit_name = linux_systemd_unit_name(spec.label);
    run_checked(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    run_checked(Command::new("systemctl").args(["--user", "enable", "--now", &unit_name]))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    let unit_name = linux_systemd_unit_name(spec.label);
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", &unit_name])
        .status();
    let unit_path = linux_systemd_user_unit_path(spec.label)?;
    if unit_path.exists() {
        std::fs::remove_file(unit_path).map_err(LpmError::Io)?;
    }
    if spec.launcher_path.exists() {
        std::fs::remove_file(&spec.launcher_path).map_err(LpmError::Io)?;
    }
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    Ok(())
}

#[cfg(windows)]
fn install_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    write_windows_launcher(spec)?;
    run_checked(
        Command::new("schtasks")
            .arg("/Create")
            .arg("/TN")
            .arg(windows_task_name(spec.label))
            .arg("/SC")
            .arg("ONLOGON")
            .arg("/TR")
            .arg(quote_windows_task_command(&spec.launcher_path))
            .arg("/RL")
            .arg("LIMITED")
            .arg("/F"),
    )?;
    run_checked(
        Command::new("schtasks")
            .arg("/Run")
            .arg("/TN")
            .arg(windows_task_name(spec.label)),
    )?;
    Ok(())
}

#[cfg(windows)]
fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    let _ = Command::new("schtasks")
        .arg("/End")
        .arg("/TN")
        .arg(windows_task_name(spec.label))
        .status();
    let _ = Command::new("schtasks")
        .arg("/Delete")
        .arg("/TN")
        .arg(windows_task_name(spec.label))
        .arg("/F")
        .status();
    if spec.launcher_path.exists() {
        std::fs::remove_file(&spec.launcher_path).map_err(LpmError::Io)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn install_proxy_service_platform(_spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    Err(LpmError::Script(
        "`lpm proxy install` is not supported on this platform".into(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn uninstall_proxy_service_platform(_spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    Err(LpmError::Script(
        "`lpm proxy uninstall` is not supported on this platform".into(),
    ))
}

#[cfg(target_os = "linux")]
fn install_privileged_forwarder_platform(spec: &PrivilegedForwarderSpec) -> Result<(), LpmError> {
    reject_conflicting_privileged_forwarder_owner(
        &spec.config_path,
        spec.config.target_uid,
        spec.replace_existing,
    )?;
    let config_source = write_privileged_staging_file(
        spec,
        "proxy-forwarder.json",
        &serde_json::to_string_pretty(&spec.config)
            .map_err(|err| LpmError::Script(err.to_string()))?,
    )?;
    let unit_source = write_privileged_staging_file(
        spec,
        "proxy-forwarder.service",
        &render_linux_forwarder_systemd_unit(spec),
    )?;
    install_root_file(&config_source, &spec.config_path, "0644")?;
    install_root_file(&unit_source, &spec.service_path, "0644")?;
    run_checked_inherited(Command::new("sudo").args(["systemctl", "daemon-reload"]))?;
    run_checked_inherited(Command::new("sudo").args([
        "systemctl",
        "enable",
        "--now",
        &linux_systemd_unit_name(spec.label),
    ]))?;
    let _ = std::fs::remove_file(config_source);
    let _ = std::fs::remove_file(unit_source);
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_privileged_forwarder_platform(spec: &PrivilegedForwarderSpec) -> Result<(), LpmError> {
    reject_removing_foreign_privileged_forwarder(&spec.config_path, spec.config.target_uid)?;
    let _ = Command::new("sudo")
        .args([
            "systemctl",
            "disable",
            "--now",
            &linux_systemd_unit_name(spec.label),
        ])
        .status();
    run_checked_inherited(
        Command::new("sudo")
            .arg("rm")
            .arg("-f")
            .arg(&spec.service_path),
    )?;
    run_checked_inherited(
        Command::new("sudo")
            .arg("rm")
            .arg("-f")
            .arg(&spec.config_path),
    )?;
    let _ = Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status();
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_privileged_forwarder_platform(spec: &PrivilegedForwarderSpec) -> Result<(), LpmError> {
    reject_conflicting_privileged_forwarder_owner(
        &spec.config_path,
        spec.config.target_uid,
        spec.replace_existing,
    )?;
    let config_source = write_privileged_staging_file(
        spec,
        "proxy-forwarder.json",
        &serde_json::to_string_pretty(&spec.config)
            .map_err(|err| LpmError::Script(err.to_string()))?,
    )?;
    let plist_source = write_privileged_staging_file(
        spec,
        "proxy-forwarder.plist",
        &render_macos_forwarder_launch_daemon_plist(spec),
    )?;
    install_root_file(&config_source, &spec.config_path, "0644")?;
    install_root_file(&plist_source, &spec.service_path, "0644")?;
    let target = macos_system_launchctl_target(spec.label);
    let _ = Command::new("sudo")
        .args(["launchctl", "bootout", &target])
        .status();
    run_checked_inherited(
        Command::new("sudo")
            .args(["launchctl", "bootstrap", "system"])
            .arg(&spec.service_path),
    )?;
    run_checked_inherited(Command::new("sudo").args(["launchctl", "enable", &target]))?;
    run_checked_inherited(Command::new("sudo").args(["launchctl", "kickstart", "-k", &target]))?;
    let _ = std::fs::remove_file(config_source);
    let _ = std::fs::remove_file(plist_source);
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_privileged_forwarder_platform(spec: &PrivilegedForwarderSpec) -> Result<(), LpmError> {
    reject_removing_foreign_privileged_forwarder(&spec.config_path, spec.config.target_uid)?;
    let target = macos_system_launchctl_target(spec.label);
    let _ = Command::new("sudo")
        .args(["launchctl", "bootout", &target])
        .status();
    run_checked_inherited(
        Command::new("sudo")
            .arg("rm")
            .arg("-f")
            .arg(&spec.service_path),
    )?;
    run_checked_inherited(
        Command::new("sudo")
            .arg("rm")
            .arg("-f")
            .arg(&spec.config_path),
    )?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn install_privileged_forwarder_platform(_spec: &PrivilegedForwarderSpec) -> Result<(), LpmError> {
    Err(LpmError::Script(
        "`lpm proxy install --privileged-ports` is only supported on Linux and macOS".into(),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn uninstall_privileged_forwarder_platform(
    _spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    Err(LpmError::Script(
        "`lpm proxy uninstall --privileged-ports` is only supported on Linux and macOS".into(),
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_privileged_staging_file(
    spec: &PrivilegedForwarderSpec,
    file_name: &str,
    contents: &str,
) -> Result<PathBuf, LpmError> {
    let lpm_home = spec.config.state_path.parent().ok_or_else(|| {
        LpmError::Script(format!(
            "proxy state path has no parent: {}",
            spec.config.state_path.display()
        ))
    })?;
    let staging_dir = lpm_home.join("services").join("proxy");
    std::fs::create_dir_all(&staging_dir).map_err(LpmError::Io)?;
    let path = staging_dir.join(file_name);
    std::fs::write(&path, contents).map_err(LpmError::Io)?;
    Ok(path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn install_root_file(source: &Path, destination: &Path, mode: &str) -> Result<(), LpmError> {
    if let Some(parent) = destination.parent() {
        run_checked_inherited(Command::new("sudo").arg("mkdir").arg("-p").arg(parent))?;
    }
    run_checked_inherited(
        Command::new("sudo")
            .arg("install")
            .arg("-m")
            .arg(mode)
            .arg(source)
            .arg(destination),
    )
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_path(label: &str) -> Result<PathBuf, LpmError> {
    let home = dirs::home_dir().ok_or_else(|| {
        LpmError::Script("could not determine home directory for LaunchAgent install".into())
    })?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist")))
}

#[cfg(target_os = "macos")]
fn macos_gui_domain() -> String {
    // SAFETY: `getuid` has no preconditions and does not dereference pointers.
    format!("gui/{}", unsafe { libc::getuid() })
}

#[cfg(target_os = "macos")]
fn macos_launchctl_target(label: &str) -> String {
    format!("{}/{}", macos_gui_domain(), label)
}

#[cfg(target_os = "macos")]
fn macos_system_launchctl_target(label: &str) -> String {
    format!("system/{label}")
}

#[cfg(any(test, target_os = "macos"))]
fn render_macos_launch_agent_plist(spec: &ProxyServiceSpec) -> String {
    let mut args = String::new();
    args.push_str(&format!(
        "    <string>{}</string>\n",
        xml_escape(&spec.exe.display().to_string())
    ));
    for arg in &spec.start_args {
        args.push_str(&format!("    <string>{}</string>\n", xml_escape(arg)));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>WorkingDirectory</key>
  <string>{working_dir}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>LPM_HOME</key>
    <string>{lpm_home}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{stdout_log}</string>
  <key>StandardErrorPath</key>
  <string>{stderr_log}</string>
</dict>
</plist>
"#,
        label = xml_escape(spec.label),
        working_dir = xml_escape(&spec.working_dir.display().to_string()),
        lpm_home = xml_escape(&spec.lpm_home.display().to_string()),
        stdout_log = xml_escape(&spec.stdout_log.display().to_string()),
        stderr_log = xml_escape(&spec.stderr_log.display().to_string()),
    )
}

#[cfg(any(test, target_os = "macos"))]
fn render_macos_forwarder_launch_daemon_plist(spec: &PrivilegedForwarderSpec) -> String {
    let mut args = String::new();
    args.push_str(&format!(
        "    <string>{}</string>\n",
        xml_escape(&spec.exe.display().to_string())
    ));
    for arg in &spec.start_args {
        args.push_str(&format!("    <string>{}</string>\n", xml_escape(arg)));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{stdout_log}</string>
  <key>StandardErrorPath</key>
  <string>{stderr_log}</string>
</dict>
</plist>
"#,
        label = xml_escape(spec.label),
        stdout_log = xml_escape(&spec.stdout_log.display().to_string()),
        stderr_log = xml_escape(&spec.stderr_log.display().to_string()),
    )
}

#[cfg(target_os = "linux")]
fn linux_systemd_user_unit_path(label: &str) -> Result<PathBuf, LpmError> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .ok_or_else(|| {
            LpmError::Script("could not determine config directory for systemd user unit".into())
        })?;
    Ok(config_home
        .join("systemd")
        .join("user")
        .join(linux_systemd_unit_name(label)))
}

#[cfg(target_os = "linux")]
fn linux_systemd_unit_name(label: &str) -> String {
    format!("{label}.service")
}

#[cfg(any(test, target_os = "linux"))]
fn render_linux_systemd_unit(spec: &ProxyServiceSpec) -> String {
    format!(
        r#"[Unit]
Description=LPM local-domain proxy
After=network.target

[Service]
Type=simple
WorkingDirectory={working_dir}
Environment=LPM_HOME={lpm_home}
ExecStart={launcher}
Restart=on-failure
RestartSec=2
StandardOutput=append:{stdout_log}
StandardError=append:{stderr_log}

[Install]
WantedBy=default.target
"#,
        working_dir = systemd_path_value(&spec.working_dir),
        lpm_home = systemd_quote(&spec.lpm_home.display().to_string()),
        launcher = systemd_quote(&spec.launcher_path.display().to_string()),
        stdout_log = systemd_path_value(&spec.stdout_log),
        stderr_log = systemd_path_value(&spec.stderr_log),
    )
}

#[cfg(any(test, target_os = "linux"))]
fn render_linux_forwarder_systemd_unit(spec: &PrivilegedForwarderSpec) -> String {
    format!(
        r#"[Unit]
Description=LPM privileged local-domain proxy forwarder
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log
StandardOutput=append:{stdout_log}
StandardError=append:{stderr_log}

[Install]
WantedBy=multi-user.target
"#,
        command = systemd_command(&spec.exe, &spec.start_args),
        stdout_log = systemd_path_value(&spec.stdout_log),
        stderr_log = systemd_path_value(&spec.stderr_log),
    )
}

#[cfg(target_os = "linux")]
fn write_unix_launcher(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Some(parent) = spec.launcher_path.parent() {
            std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
        }
        let script = render_unix_launcher(spec);
        std::fs::write(&spec.launcher_path, script).map_err(LpmError::Io)?;
        std::fs::set_permissions(&spec.launcher_path, std::fs::Permissions::from_mode(0o700))
            .map_err(LpmError::Io)?;
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn render_unix_launcher(spec: &ProxyServiceSpec) -> String {
    let mut command = Vec::with_capacity(1 + spec.start_args.len());
    command.push(spec.exe.display().to_string());
    command.extend(spec.start_args.iter().cloned());
    let command = command
        .iter()
        .map(|arg| shlex::try_quote(arg).unwrap_or_else(|_| arg.into()))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "#!/bin/sh\nexport LPM_HOME={}\ncd {} || exit 1\nexec {command}\n",
        shlex::try_quote(&spec.lpm_home.display().to_string()).unwrap_or_default(),
        shlex::try_quote(&spec.working_dir.display().to_string()).unwrap_or_default(),
    )
}

#[cfg(windows)]
fn write_windows_launcher(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    if let Some(parent) = spec.launcher_path.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }
    std::fs::write(&spec.launcher_path, render_windows_launcher(spec)).map_err(LpmError::Io)
}

#[cfg(any(test, windows))]
fn render_windows_launcher(spec: &ProxyServiceSpec) -> String {
    let mut command = Vec::with_capacity(1 + spec.start_args.len());
    command.push(spec.exe.display().to_string());
    command.extend(spec.start_args.iter().cloned());
    format!(
        "@echo off\r\nset \"LPM_HOME={}\"\r\ncd /d \"{}\" || exit /b 1\r\n{}\r\n",
        spec.lpm_home.display(),
        spec.working_dir.display(),
        quote_windows_command(&command),
    )
}

#[cfg(windows)]
fn windows_task_name(_label: &str) -> &'static str {
    r"\LPM\Proxy"
}

#[cfg(windows)]
fn quote_windows_task_command(path: &Path) -> String {
    quote_windows_command(&[path.display().to_string()])
}

#[cfg(any(test, windows))]
fn quote_windows_command(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(test, windows))]
fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if !arg
        .bytes()
        .any(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\\'))
    {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                quoted.push('\\');
            }
            quoted.push('"');
            backslashes = 0;
            continue;
        }
        for _ in 0..backslashes {
            quoted.push('\\');
        }
        backslashes = 0;
        quoted.push(ch);
    }
    for _ in 0..(backslashes * 2) {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

fn run_checked(command: &mut Command) -> Result<(), LpmError> {
    let output = command.output().map_err(LpmError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(LpmError::Script(format!(
        "`{}` failed with {}{}{}",
        format_command_for_error(command),
        output.status,
        if stderr.trim().is_empty() { "" } else { ": " },
        if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        }
    )))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_checked_inherited(command: &mut Command) -> Result<(), LpmError> {
    let status = command.status().map_err(LpmError::Io)?;
    if status.success() {
        return Ok(());
    }
    Err(LpmError::Script(format!(
        "`{}` failed with {status}",
        format_command_for_error(command),
    )))
}

fn format_command_for_error(command: &Command) -> String {
    let mut parts = Vec::new();
    parts.push(command.get_program().to_string_lossy().to_string());
    parts.extend(
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string()),
    );
    parts.join(" ")
}

#[cfg(any(test, target_os = "macos"))]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(test, target_os = "linux"))]
fn systemd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(any(test, target_os = "linux"))]
fn systemd_command(exe: &Path, args: &[String]) -> String {
    std::iter::once(exe.display().to_string())
        .chain(args.iter().cloned())
        .map(|arg| systemd_quote(&arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(test, target_os = "linux"))]
fn systemd_path_value(path: &Path) -> String {
    let value = path.display().to_string();
    let mut escaped = String::with_capacity(value.len());
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for byte in value.bytes() {
        match byte {
            b'/' | b'.' | b'_' | b'-' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => {
                escaped.push(byte as char);
            }
            _ => {
                escaped.push('\\');
                escaped.push('x');
                escaped.push(HEX[(byte >> 4) as usize] as char);
                escaped.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_start_options_keeps_control_only_without_local_domain_config() {
        let dir = tempfile::tempdir().unwrap();

        let options = resolve_start_options(dir.path(), None, None, None).unwrap();

        assert_eq!(options, lpm_proxy::ProxyDaemonOptions::default());
    }

    #[test]
    fn resolve_start_options_uses_proxy_port_and_redirect_setting_from_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"proxy":{"host":"app.localhost","port":9443,"httpRedirect":false}}"#,
        )
        .unwrap();

        let options = resolve_start_options(dir.path(), None, None, None).unwrap();

        assert_eq!(
            options,
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: None,
                tls_port: Some(9443),
            }
        );
    }

    #[test]
    fn resolve_start_options_defaults_proxy_listener_for_service_hosts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"services":{"web":{"command":"node server.js","host":"web.localhost"}}}"#,
        )
        .unwrap();

        let options = resolve_start_options(dir.path(), None, None, None).unwrap();

        assert_eq!(
            options,
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(80),
                tls_port: Some(443),
            }
        );
    }

    #[test]
    fn resolve_start_options_keeps_explicit_listener_flags_over_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"proxy":{"host":"app.localhost","port":9443,"httpRedirect":true}}"#,
        )
        .unwrap();

        let options = resolve_start_options(dir.path(), Some(8080), None, None).unwrap();

        assert_eq!(
            options,
            lpm_proxy::ProxyDaemonOptions {
                http_port: Some(8080),
                http_redirect_port: None,
                tls_port: None,
            }
        );
    }

    #[test]
    fn proxy_service_start_args_use_resolved_listener_options() {
        let args = listener_args(lpm_proxy::ProxyDaemonOptions {
            http_port: None,
            http_redirect_port: Some(8080),
            tls_port: Some(9443),
        });

        assert_eq!(
            args,
            vec!["--tls-port", "9443", "--http-redirect-port", "8080",]
        );
    }

    #[cfg(unix)]
    #[test]
    fn proxy_service_install_rejects_privileged_user_service_ports() {
        let err = reject_privileged_user_service_ports(lpm_proxy::ProxyDaemonOptions {
            http_port: None,
            http_redirect_port: Some(80),
            tls_port: Some(443),
        })
        .unwrap_err();

        assert!(err.to_string().contains("privileged port"), "got {err}");
        assert!(
            err.to_string().contains("proxy install --privileged-ports"),
            "got {err}"
        );
        assert!(err.to_string().contains("9443"), "got {err}");
        assert!(!err.to_string().contains("not wired yet"), "got {err}");
    }

    #[test]
    fn proxy_service_install_allows_high_and_ephemeral_ports() {
        reject_privileged_user_service_ports(lpm_proxy::ProxyDaemonOptions {
            http_port: Some(0),
            http_redirect_port: Some(8080),
            tls_port: Some(9443),
        })
        .unwrap();
    }

    #[test]
    fn privileged_external_options_defaults_to_low_https_and_redirect_ports() {
        let options =
            privileged_external_options(lpm_proxy::ProxyDaemonOptions::default(), false).unwrap();

        assert_eq!(
            options,
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(80),
                tls_port: Some(443),
            }
        );
    }

    #[test]
    fn privileged_external_options_maps_config_high_ports_to_low_external_ports() {
        let options = privileged_external_options(
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(9080),
                tls_port: Some(9443),
            },
            false,
        )
        .unwrap();

        assert_eq!(
            options,
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(80),
                tls_port: Some(443),
            }
        );
    }

    #[test]
    fn privileged_external_options_preserves_config_redirect_disabled() {
        let options = privileged_external_options(
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: None,
                tls_port: Some(9443),
            },
            false,
        )
        .unwrap();

        assert_eq!(
            options,
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: None,
                tls_port: Some(443),
            }
        );
    }

    #[test]
    fn privileged_external_options_rejects_plain_http_forwarding() {
        let err = privileged_external_options(
            lpm_proxy::ProxyDaemonOptions {
                http_port: Some(80),
                http_redirect_port: None,
                tls_port: None,
            },
            true,
        )
        .unwrap_err();

        assert!(err.to_string().contains("plain `--http-port`"), "got {err}");
    }

    #[test]
    fn privileged_external_options_rejects_high_external_tls_port() {
        let err = validate_privileged_external_options(lpm_proxy::ProxyDaemonOptions {
            http_port: None,
            http_redirect_port: None,
            tls_port: Some(9443),
        })
        .unwrap_err();

        assert!(err.to_string().contains("does not need"), "got {err}");
    }

    #[test]
    fn privileged_forwarder_config_maps_low_listeners_to_backend_targets() {
        let config = PrivilegedForwarderConfig::new(
            501,
            PathBuf::from("/tmp/lpm home/proxy.json"),
            PathBuf::from("/tmp/LPM Bin/lpm-rs"),
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(80),
                tls_port: Some(443),
            },
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(9080),
                tls_port: Some(9443),
            },
        )
        .unwrap();

        assert_eq!(
            config.rules,
            vec![
                PrivilegedForwarderRuleConfig {
                    name: "https".to_string(),
                    listen_addr: loopback_socket_addr(443),
                    target_addr: loopback_socket_addr(9443),
                },
                PrivilegedForwarderRuleConfig {
                    name: "httpRedirect".to_string(),
                    listen_addr: loopback_socket_addr(80),
                    target_addr: loopback_socket_addr(9080),
                },
            ]
        );
    }

    #[test]
    fn privileged_forwarder_owner_check_allows_same_uid_reinstall() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("proxy-forwarder.json");
        write_forwarder_config(&config_path, 501);

        reject_conflicting_privileged_forwarder_owner(&config_path, 501, false).unwrap();
    }

    #[test]
    fn privileged_forwarder_owner_check_rejects_other_uid_takeover() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("proxy-forwarder.json");
        write_forwarder_config(&config_path, 501);

        let err =
            reject_conflicting_privileged_forwarder_owner(&config_path, 502, false).unwrap_err();

        assert!(
            err.to_string().contains("already owned by UID 501"),
            "got {err}"
        );
        assert!(err.to_string().contains("--replace"), "got {err}");
    }

    #[test]
    fn privileged_forwarder_owner_check_allows_explicit_replace_for_other_uid() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("proxy-forwarder.json");
        write_forwarder_config(&config_path, 501);

        reject_conflicting_privileged_forwarder_owner(&config_path, 502, true).unwrap();
    }

    #[test]
    fn privileged_forwarder_remove_check_rejects_other_uid_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("proxy-forwarder.json");
        write_forwarder_config(&config_path, 501);

        let err = reject_removing_foreign_privileged_forwarder(&config_path, 502).unwrap_err();

        assert!(err.to_string().contains("owned by UID 501"), "got {err}");
    }

    #[test]
    fn privileged_forwarder_cleanup_error_names_remaining_root_artifacts() {
        let spec = sample_forwarder_spec();
        let message = format_privileged_forwarder_cleanup_error(
            &LpmError::Script("sudo failed".into()),
            &spec,
        );

        assert!(message.contains("sudo failed"), "got {message}");
        assert!(
            message.contains("/etc/systemd/system/dev.lpm.proxy.forwarder.service"),
            "got {message}"
        );
        assert!(
            message.contains("/etc/lpm/proxy-forwarder.json"),
            "got {message}"
        );
    }

    #[test]
    fn macos_launch_agent_plist_contains_program_args_and_lpm_home() {
        let spec = sample_service_spec();

        let plist = render_macos_launch_agent_plist(&spec);

        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<string>/tmp/LPM Bin/lpm-rs</string>"));
        assert!(plist.contains("<string>--tls-port</string>"));
        assert!(plist.contains("<string>9443</string>"));
        assert!(plist.contains("<key>LPM_HOME</key>"));
        assert!(plist.contains("<string>/tmp/lpm home</string>"));
    }

    #[test]
    fn linux_systemd_unit_uses_launcher_and_lpm_home_environment() {
        let spec = sample_service_spec();

        let unit = render_linux_systemd_unit(&spec);

        assert!(unit.contains("Environment=LPM_HOME=\"/tmp/lpm home\""));
        assert!(unit.contains("ExecStart=\"/tmp/lpm home/services/proxy/start-proxy.sh\""));
        assert!(unit.contains("Restart=on-failure"));
    }

    #[test]
    fn linux_systemd_unit_path_directives_are_unquoted_absolute_paths() {
        let spec = sample_service_spec();

        let unit = render_linux_systemd_unit(&spec);

        assert!(
            unit.contains("WorkingDirectory=/tmp/project\\x20dir"),
            "systemd rejects quoted WorkingDirectory paths:\n{unit}"
        );
        assert!(
            unit.contains("StandardOutput=append:/tmp/lpm\\x20home/services/proxy/proxy.out.log"),
            "systemd rejects quoted StandardOutput append paths:\n{unit}"
        );
    }

    #[test]
    fn linux_forwarder_systemd_unit_execs_hidden_forwarder_with_hardening() {
        let spec = sample_forwarder_spec();

        let unit = render_linux_forwarder_systemd_unit(&spec);

        assert!(unit.contains("Description=LPM privileged local-domain proxy forwarder"));
        assert!(unit.contains(
            "ExecStart=\"/tmp/LPM Bin/lpm-rs\" \"proxy\" \"forwarder\" \"--forwarder-config\""
        ));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("StandardOutput=append:/var/log/lpm-proxy-forwarder.out.log"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn unix_launcher_execs_proxy_start_with_quoted_paths() {
        let spec = sample_service_spec();

        let launcher = render_unix_launcher(&spec);

        assert!(launcher.contains("export LPM_HOME='/tmp/lpm home'"));
        assert!(launcher.contains("cd '/tmp/project dir' || exit 1"));
        assert!(launcher.contains("exec '/tmp/LPM Bin/lpm-rs' proxy start --tls-port 9443"));
    }

    #[test]
    fn windows_launcher_quotes_paths_and_start_arguments() {
        let spec = sample_service_spec();

        let launcher = render_windows_launcher(&spec);

        assert!(launcher.contains("set \"LPM_HOME=/tmp/lpm home\""));
        assert!(launcher.contains("cd /d \"/tmp/project dir\" || exit /b 1"));
        assert!(launcher.contains("\"/tmp/LPM Bin/lpm-rs\" proxy start --tls-port 9443"));
    }

    #[test]
    fn macos_forwarder_launch_daemon_execs_hidden_forwarder_config() {
        let spec = sample_forwarder_spec();

        let plist = render_macos_forwarder_launch_daemon_plist(&spec);

        assert!(plist.contains("<string>dev.lpm.proxy.forwarder</string>"));
        assert!(plist.contains("<string>/tmp/LPM Bin/lpm-rs</string>"));
        assert!(plist.contains("<string>forwarder</string>"));
        assert!(plist.contains("<string>--forwarder-config</string>"));
        assert!(plist.contains("<string>/etc/lpm/proxy-forwarder.json</string>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
    }

    fn sample_service_spec() -> ProxyServiceSpec {
        ProxyServiceSpec {
            label: "dev.lpm.proxy",
            exe: PathBuf::from("/tmp/LPM Bin/lpm-rs"),
            working_dir: PathBuf::from("/tmp/project dir"),
            lpm_home: PathBuf::from("/tmp/lpm home"),
            start_args: vec![
                "proxy".to_string(),
                "start".to_string(),
                "--tls-port".to_string(),
                "9443".to_string(),
            ],
            launcher_path: PathBuf::from("/tmp/lpm home/services/proxy/start-proxy.sh"),
            stdout_log: PathBuf::from("/tmp/lpm home/services/proxy/proxy.out.log"),
            stderr_log: PathBuf::from("/tmp/lpm home/services/proxy/proxy.err.log"),
        }
    }

    fn sample_forwarder_spec() -> PrivilegedForwarderSpec {
        let backend_options = lpm_proxy::ProxyDaemonOptions {
            http_port: None,
            http_redirect_port: Some(9080),
            tls_port: Some(9443),
        };
        let config = PrivilegedForwarderConfig::new(
            501,
            PathBuf::from("/tmp/lpm home/proxy.json"),
            PathBuf::from("/tmp/LPM Bin/lpm-rs"),
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(80),
                tls_port: Some(443),
            },
            backend_options,
        )
        .unwrap();
        PrivilegedForwarderSpec {
            label: "dev.lpm.proxy.forwarder",
            exe: PathBuf::from("/tmp/LPM Bin/lpm-rs"),
            start_args: vec![
                "proxy".to_string(),
                "forwarder".to_string(),
                "--forwarder-config".to_string(),
                "/etc/lpm/proxy-forwarder.json".to_string(),
            ],
            config_path: PathBuf::from("/etc/lpm/proxy-forwarder.json"),
            service_path: PathBuf::from("/etc/systemd/system/dev.lpm.proxy.forwarder.service"),
            stdout_log: PathBuf::from("/var/log/lpm-proxy-forwarder.out.log"),
            stderr_log: PathBuf::from("/var/log/lpm-proxy-forwarder.err.log"),
            backend_options,
            config,
            replace_existing: false,
        }
    }

    fn write_forwarder_config(path: &Path, target_uid: u32) {
        let config = PrivilegedForwarderConfig::new(
            target_uid,
            PathBuf::from("/tmp/lpm home/proxy.json"),
            PathBuf::from("/tmp/LPM Bin/lpm-rs"),
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(80),
                tls_port: Some(443),
            },
            lpm_proxy::ProxyDaemonOptions {
                http_port: None,
                http_redirect_port: Some(9080),
                tls_port: Some(9443),
            },
        )
        .unwrap();
        std::fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
    }
}
