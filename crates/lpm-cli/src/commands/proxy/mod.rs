mod proxy_platform;
mod proxy_service;

#[cfg(test)]
mod tests;

use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_proxy::ProxyStatus;
use lpm_runner::lpm_json;
use std::path::Path;
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
        "install" => proxy_service::run_install(
            project_dir,
            json_output,
            privileged_ports,
            replace,
            http_port,
            http_redirect_port,
            tls_port,
        ),
        "uninstall" => proxy_service::run_uninstall(json_output, privileged_ports),
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
    if proxy_service::current_effective_uid() != 0 {
        return Err(LpmError::Script(
            "the internal proxy forwarder must run as root".into(),
        ));
    }
    let bytes = std::fs::read(config_path).map_err(LpmError::Io)?;
    let config: proxy_service::PrivilegedForwarderConfig =
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
    #[cfg(windows)]
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

#[cfg(windows)]
fn prepare_detached_spawn_handles() -> std::io::Result<()> {
    clear_standard_handle_inheritance()
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

pub(super) fn listener_args(options: lpm_proxy::ProxyDaemonOptions) -> Vec<String> {
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

pub(super) fn resolve_start_options(
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
