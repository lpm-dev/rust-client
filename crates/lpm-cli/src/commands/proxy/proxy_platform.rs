#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::forwarder_executable::{install_forwarder_executable, uninstall_forwarder_executable};
use super::proxy_service::{PrivilegedForwarderSpec, ProxyServiceSpec};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::proxy_service::{
    reject_conflicting_privileged_forwarder_owner, reject_removing_foreign_privileged_forwarder,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::root_fs::{privileged_command, write_root_file};
use lpm_common::LpmError;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
use std::process::Command;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn trusted_sudo() -> Result<&'static Path, LpmError> {
    crate::elevation::trusted_sudo().ok_or_else(|| {
        LpmError::Proxy(crate::elevation::trusted_sudo_not_found_message(
            "proxy forwarder",
        ))
    })
}

#[cfg(target_os = "macos")]
pub(super) fn install_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    let plist_path = macos_launch_agent_path(spec.label)?;
    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }
    if let Some(parent) = spec.stdout_log.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }
    std::fs::write(&plist_path, render_macos_launch_agent_plist(spec)).map_err(LpmError::Io)?;

    let target = macos_launchctl_target(spec.label);
    run_macos_bootout(Command::new("launchctl").args(["bootout", &target]))?;
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

/// Removes the user service, and says whether there was one.
#[cfg(target_os = "macos")]
pub(super) fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<bool, LpmError> {
    let target = macos_launchctl_target(spec.label);
    uninstall_macos_user_agent(Path::new("launchctl"), &target)?;
    let plist_path = macos_launch_agent_path(spec.label)?;
    let installed = plist_path.exists();
    if installed {
        std::fs::remove_file(plist_path).map_err(LpmError::Io)?;
    }
    Ok(installed)
}

#[cfg(target_os = "linux")]
pub(super) fn install_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    write_unix_launcher(spec)?;
    let unit_path = linux_systemd_user_unit_path(spec.label)?;
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }
    std::fs::write(&unit_path, render_linux_systemd_unit(spec)).map_err(LpmError::Io)?;
    let unit_name = linux_systemd_unit_name(spec.label);
    install_linux_user_unit(Path::new("systemctl"), &unit_name)?;
    Ok(())
}

/// Removes the user service, and says whether there was one.
#[cfg(target_os = "linux")]
pub(super) fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<bool, LpmError> {
    let unit_name = linux_systemd_unit_name(spec.label);
    let unit_path = linux_systemd_user_unit_path(spec.label)?;
    let installed = unit_path.exists();
    uninstall_linux_user_unit(Path::new("systemctl"), &unit_name)?;
    if installed {
        std::fs::remove_file(unit_path).map_err(LpmError::Io)?;
    }
    if spec.launcher_path.exists() {
        std::fs::remove_file(&spec.launcher_path).map_err(LpmError::Io)?;
    }
    run_checked(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    Ok(installed)
}

/// Registers a task that starts the proxy when this user signs in, in no
/// window. Its logon trigger is this user's alone: one for any user's
/// logon, which `schtasks /SC ONLOGON` makes, needs an administrator.
#[cfg(windows)]
pub(super) fn install_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    let user = windows_user_sid()?;
    let spec = windows_plain_spec(spec)?;
    let system = lpm_common::platform::windows_system_directory().map_err(|error| {
        LpmError::Proxy(format!(
            "couldn't find the Windows system directory: {error}"
        ))
    })?;
    let schtasks = Path::new("schtasks");
    let task = windows_task_name(&user);
    // The task's run ends once the proxy has started, so ending the task
    // stops nothing. The proxy the task started, with whatever home it
    // gave it, is asked to stop, and so is one running for this home, as
    // one started by hand would be, so that the task's can take the pipe
    // and the listeners.
    if windows_user_task_exists(schtasks, &task)?
        && let Some(home) = windows_installed_task_home(schtasks, &task)
        && !same_proxy_home(&home, &spec.lpm_home)
    {
        stop_windows_proxy(&spec.exe, &home);
    }
    stop_windows_proxy(&spec.exe, &spec.lpm_home);
    let left_running = windows_running_proxy(&spec.exe, &spec.lpm_home);
    remove_earlier_windows_launcher(&spec)?;
    let service_dir = spec
        .stdout_log
        .parent()
        .ok_or_else(|| LpmError::Proxy("the proxy log has no directory".into()))?;
    std::fs::create_dir_all(service_dir).map_err(LpmError::Io)?;
    let task_file = service_dir.join("proxy-task.xml");
    write_windows_task_xml(&task_file, &render_windows_task_xml(&spec, &user, &system))?;
    let installed = install_windows_user_task(schtasks, &task, &task_file);
    let _ = std::fs::remove_file(&task_file);
    installed?;
    // The task's result can't tell, as conhost ends with 0 whatever lpm did.
    match windows_proxy_after_start(&spec, left_running, std::time::Duration::from_secs(10)) {
        Some(pid) if Some(pid) == left_running => tracing::warn!(
            "a proxy the sign-in task didn't start (pid {pid}) is still running for {}, so the \
             task's couldn't start; stop it with `lpm proxy stop`, then run `lpm proxy install` \
             again",
            spec.lpm_home.display()
        ),
        Some(_) => {}
        None => tracing::warn!(
            "the proxy the sign-in task started isn't running; {} says why",
            spec.stderr_log.display()
        ),
    }
    if windows_user_task_exists(schtasks, WINDOWS_EARLIER_TASK_NAME).unwrap_or(false) {
        tracing::warn!(
            "the task an earlier LPM release made, {WINDOWS_EARLIER_TASK_NAME}, also starts a proxy \
             when anyone signs in; remove it from an administrator terminal with \
             `schtasks /Delete /TN {WINDOWS_EARLIER_TASK_NAME} /F`"
        );
    }
    Ok(())
}

/// Stops the proxy this user's task started, with the home the task gives
/// it whatever `LPM_HOME` this runs with, and removes the task, and the one
/// earlier releases made for anyone's logon, and says whether there was
/// one. That earlier task needs an administrator to remove: when it can't
/// be, this user's is still removed, and the error says what is left.
#[cfg(windows)]
pub(super) fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<bool, LpmError> {
    let user = windows_user_sid()?;
    let schtasks = Path::new("schtasks");
    let task = windows_task_name(&user);
    let installed = windows_user_task_exists(schtasks, &task)?;
    let earlier = windows_user_task_exists(schtasks, WINDOWS_EARLIER_TASK_NAME)?;
    let task_home = installed.then(|| {
        windows_installed_task_home(schtasks, &task).unwrap_or_else(|| spec.lpm_home.clone())
    });
    if let Some(home) = &task_home {
        stop_windows_proxy(&spec.exe, home);
    }
    // The earlier task's batch file held the home it ran the proxy with,
    // which was this one's unless `LPM_HOME` has changed since.
    if earlier
        && task_home
            .as_ref()
            .is_none_or(|home| !same_proxy_home(home, &spec.lpm_home))
    {
        stop_windows_proxy(&spec.exe, &spec.lpm_home);
    }
    if installed {
        uninstall_windows_user_task(schtasks, &task)?;
    }
    remove_earlier_windows_launcher(spec)?;
    if earlier {
        uninstall_windows_user_task(schtasks, WINDOWS_EARLIER_TASK_NAME).map_err(|error| {
            LpmError::Proxy(format!(
                "{}couldn't remove the task an earlier LPM release made, \
                 {WINDOWS_EARLIER_TASK_NAME}, which starts a proxy when anyone signs in: {error}; \
                 remove it from an administrator terminal with \
                 `schtasks /Delete /TN {WINDOWS_EARLIER_TASK_NAME} /F`",
                if installed {
                    "removed this user's proxy service, but "
                } else {
                    ""
                }
            ))
        })?;
    }
    Ok(installed || earlier)
}

/// Whether the proxies for LPM homes `a` and `b` are one, as they answer
/// on one control pipe.
#[cfg(windows)]
fn same_proxy_home(a: &Path, b: &Path) -> bool {
    lpm_proxy::proxy_pipe_name_for_root(a) == lpm_proxy::proxy_pipe_name_for_root(b)
}

/// Asks the proxy running with `home` to stop, as `lpm proxy stop` does,
/// with lpm at `exe`; one that isn't running is fine. Ending the task
/// wouldn't stop it.
#[cfg(windows)]
fn stop_windows_proxy(exe: &Path, home: &Path) {
    let stopped = Command::new(exe)
        .args(["proxy", "stop", "--json"])
        .env("LPM_HOME", home)
        .stdin(std::process::Stdio::null())
        .output();
    match stopped {
        Ok(output) if output.status.success() => {}
        Ok(output) => tracing::warn!(
            "couldn't stop the proxy running for {} ({}): {}; stop it with `lpm proxy stop`",
            home.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => {
            tracing::warn!(
                "couldn't stop the proxy running for {}: {error}; stop it with `lpm proxy stop`",
                home.display()
            );
        }
    }
}

/// The process ID of the proxy running with `home`, as `lpm proxy status`
/// gives it, run with lpm at `exe`.
#[cfg(windows)]
fn windows_running_proxy(exe: &Path, home: &Path) -> Option<u32> {
    let output = Command::new(exe)
        .args(["proxy", "status", "--json"])
        .env("LPM_HOME", home)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let status = serde_json::from_slice::<serde_json::Value>(&output.stdout).ok()?;
    if status["running"] != true {
        return None;
    }
    status["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
}

/// The process ID of the proxy running with `spec`'s home once one other
/// than `left_running` is, or when `wait` is over, of whichever runs then.
#[cfg(windows)]
fn windows_proxy_after_start(
    spec: &ProxyServiceSpec,
    left_running: Option<u32>,
    wait: std::time::Duration,
) -> Option<u32> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        let running = windows_running_proxy(&spec.exe, &spec.lpm_home);
        if running.is_some_and(|pid| Some(pid) != left_running)
            || std::time::Instant::now() >= deadline
        {
            return running;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Removes the batch file an earlier release's task ran, which none runs now.
#[cfg(windows)]
fn remove_earlier_windows_launcher(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    match std::fs::remove_file(&spec.launcher_path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(LpmError::Io(error)),
        _ => Ok(()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub(super) fn install_proxy_service_platform(_spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    Err(LpmError::Proxy(
        "`lpm proxy install` is not supported on this platform".into(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub(super) fn uninstall_proxy_service_platform(_spec: &ProxyServiceSpec) -> Result<bool, LpmError> {
    Err(LpmError::Proxy(
        "`lpm proxy uninstall` is not supported on this platform".into(),
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn install_privileged_forwarder_platform(
    spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    reject_conflicting_privileged_forwarder_owner(
        &spec.config_path,
        spec.config.target_uid,
        spec.replace_existing,
    )?;
    let sudo = trusted_sudo()?;
    install_forwarder_executable(&spec.executable, sudo)?;
    write_root_file(
        sudo,
        0,
        privileged_forwarder_config_json(spec)?.as_bytes(),
        &spec.config_path,
        "0644",
    )?;
    write_root_file(
        sudo,
        0,
        render_linux_forwarder_systemd_unit(spec).as_bytes(),
        &spec.service_path,
        "0644",
    )?;
    install_linux_forwarder_unit(sudo, &linux_systemd_unit_name(spec.label))
}

#[cfg(target_os = "linux")]
pub(super) fn uninstall_privileged_forwarder_platform(
    spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    reject_removing_foreign_privileged_forwarder(&spec.config_path, spec.config.target_uid)?;
    let sudo = trusted_sudo()?;
    let unit = linux_systemd_unit_name(spec.label);
    let state = run_checked_output(Command::new("systemctl").args([
        "show",
        "--property=LoadState",
        "--value",
        &unit,
    ]))?;
    if String::from_utf8_lossy(&state.stdout).trim() != "not-found" {
        run_checked_inherited(privileged_command(sudo).args([
            "systemctl",
            "disable",
            "--now",
            &unit,
        ]))?;
    }
    run_checked_inherited(
        privileged_command(sudo)
            .arg("rm")
            .arg("-f")
            .arg(&spec.service_path),
    )?;
    run_checked_inherited(
        privileged_command(sudo)
            .arg("rm")
            .arg("-f")
            .arg(&spec.config_path),
    )?;
    run_checked_inherited(privileged_command(sudo).args(["systemctl", "daemon-reload"]))?;
    uninstall_forwarder_executable(spec.executable.install_dir(), sudo)
}

#[cfg(target_os = "macos")]
pub(super) fn install_privileged_forwarder_platform(
    spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    reject_conflicting_privileged_forwarder_owner(
        &spec.config_path,
        spec.config.target_uid,
        spec.replace_existing,
    )?;
    let sudo = trusted_sudo()?;
    install_forwarder_executable(&spec.executable, sudo)?;
    write_root_file(
        sudo,
        0,
        privileged_forwarder_config_json(spec)?.as_bytes(),
        &spec.config_path,
        "0644",
    )?;
    write_root_file(
        sudo,
        0,
        render_macos_forwarder_launch_daemon_plist(spec).as_bytes(),
        &spec.service_path,
        "0644",
    )?;
    let target = macos_system_launchctl_target(spec.label);
    run_macos_bootout(privileged_command(sudo).args(["launchctl", "bootout", &target]))?;
    run_checked_inherited(
        privileged_command(sudo)
            .args(["launchctl", "bootstrap", "system"])
            .arg(&spec.service_path),
    )?;
    run_checked_inherited(privileged_command(sudo).args(["launchctl", "enable", &target]))?;
    run_checked_inherited(privileged_command(sudo).args(["launchctl", "kickstart", "-k", &target]))
}

#[cfg(target_os = "macos")]
pub(super) fn uninstall_privileged_forwarder_platform(
    spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    reject_removing_foreign_privileged_forwarder(&spec.config_path, spec.config.target_uid)?;
    let sudo = trusted_sudo()?;
    let target = macos_system_launchctl_target(spec.label);
    run_macos_bootout(privileged_command(sudo).args(["launchctl", "bootout", &target]))?;
    run_checked_inherited(
        privileged_command(sudo)
            .arg("rm")
            .arg("-f")
            .arg(&spec.service_path),
    )?;
    run_checked_inherited(
        privileged_command(sudo)
            .arg("rm")
            .arg("-f")
            .arg(&spec.config_path),
    )?;
    uninstall_forwarder_executable(spec.executable.install_dir(), sudo)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn install_privileged_forwarder_platform(
    _spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    Err(LpmError::Proxy(
        "`lpm proxy install --privileged-ports` is only supported on Linux and macOS".into(),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn uninstall_privileged_forwarder_platform(
    _spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    Err(LpmError::Proxy(
        "`lpm proxy uninstall --privileged-ports` is only supported on Linux and macOS".into(),
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn privileged_forwarder_config_json(spec: &PrivilegedForwarderSpec) -> Result<String, LpmError> {
    serde_json::to_string_pretty(&spec.config).map_err(|err| LpmError::Proxy(err.to_string()))
}

#[cfg(target_os = "macos")]
pub(super) fn macos_launch_agent_path(label: &str) -> Result<PathBuf, LpmError> {
    let home = dirs::home_dir().ok_or_else(|| {
        LpmError::Proxy("could not determine home directory for LaunchAgent install".into())
    })?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist")))
}

#[cfg(target_os = "macos")]
pub(super) fn macos_gui_domain() -> String {
    // SAFETY: `getuid` has no preconditions and does not dereference pointers.
    format!("gui/{}", unsafe { libc::getuid() })
}

#[cfg(target_os = "macos")]
pub(super) fn macos_launchctl_target(label: &str) -> String {
    format!("{}/{}", macos_gui_domain(), label)
}

#[cfg(target_os = "macos")]
pub(super) fn macos_system_launchctl_target(label: &str) -> String {
    format!("system/{label}")
}

#[cfg(any(test, target_os = "macos"))]
pub(super) fn render_macos_launch_agent_plist(spec: &ProxyServiceSpec) -> String {
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
pub(super) fn render_macos_forwarder_launch_daemon_plist(spec: &PrivilegedForwarderSpec) -> String {
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
pub(super) fn linux_systemd_user_unit_path(label: &str) -> Result<PathBuf, LpmError> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .ok_or_else(|| {
            LpmError::Proxy("could not determine config directory for systemd user unit".into())
        })?;
    Ok(config_home
        .join("systemd")
        .join("user")
        .join(linux_systemd_unit_name(label)))
}

#[cfg(target_os = "linux")]
pub(super) fn linux_systemd_unit_name(label: &str) -> String {
    format!("{label}.service")
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn render_linux_systemd_unit(spec: &ProxyServiceSpec) -> String {
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
pub(super) fn render_linux_forwarder_systemd_unit(spec: &PrivilegedForwarderSpec) -> String {
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
pub(super) fn write_unix_launcher(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
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
pub(super) fn render_unix_launcher(spec: &ProxyServiceSpec) -> String {
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

/// What the logon task has conhost run: lpm itself, as `lpm
/// internal-proxy-service`, which starts the proxy with the home, project
/// and logs it is given. conhost doesn't pass on its command line as it
/// was written: it splits it into arguments and joins them again, quoting
/// only those with a space in them. So the task runs nothing that reads
/// its command line any other way, such as cmd.exe.
#[cfg(any(test, windows))]
pub(super) fn windows_task_command(spec: &ProxyServiceSpec) -> Vec<String> {
    let path = |path: &Path| path.display().to_string();
    let mut command = vec![
        path(&spec.exe),
        "internal-proxy-service".to_string(),
        "--home".to_string(),
        path(&spec.lpm_home),
        "--project".to_string(),
        path(&spec.working_dir),
        "--stdout".to_string(),
        path(&spec.stdout_log),
        "--stderr".to_string(),
        path(&spec.stderr_log),
        "--".to_string(),
    ];
    command.extend(spec.start_args.iter().cloned());
    command
}

/// The task earlier releases made, for any user's logon.
#[cfg(windows)]
const WINDOWS_EARLIER_TASK_NAME: &str = r"\LPM\Proxy";

/// This user's task, by their SID: each account on a PC has its own.
#[cfg(windows)]
fn windows_task_name(user_sid: &str) -> String {
    format!(r"\LPM Proxy ({user_sid})")
}

/// What the logon task's documentation says before the LPM home it runs
/// the proxy with, as hex of its UTF-8, which schtasks prints intact in any
/// code page.
#[cfg(any(test, windows))]
const WINDOWS_TASK_HOME_LABEL: &str = "LPM_HOME as UTF-8, in hex: ";

/// The Task Scheduler definition of the logon task: this user's logon
/// starts [`windows_task_command`] in a console with no window (`conhost
/// --headless`), with this user's own rights and at normal priority, on
/// battery too. The paths go in this UTF-16 file, which holds any of them,
/// and the home also in its documentation, read by
/// [`windows_task_home`].
#[cfg(any(test, windows))]
pub(super) fn render_windows_task_xml(
    spec: &ProxyServiceSpec,
    user_sid: &str,
    system_dir: &Path,
) -> String {
    let escape = |text: &str| {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let arguments = format!(
        "--headless {}",
        quote_windows_command(&windows_task_command(spec))
    );
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
         <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
         \x20 <RegistrationInfo>\r\n\
         \x20   <Description>Starts the LPM local proxy when this user signs in.</Description>\r\n\
         {documentation}\
         \x20 </RegistrationInfo>\r\n\
         \x20 <Triggers>\r\n\
         \x20   <LogonTrigger>\r\n\
         \x20     <Enabled>true</Enabled>\r\n\
         \x20     <UserId>{user}</UserId>\r\n\
         \x20   </LogonTrigger>\r\n\
         \x20 </Triggers>\r\n\
         \x20 <Principals>\r\n\
         \x20   <Principal id=\"Author\">\r\n\
         \x20     <UserId>{user}</UserId>\r\n\
         \x20     <LogonType>InteractiveToken</LogonType>\r\n\
         \x20     <RunLevel>LeastPrivilege</RunLevel>\r\n\
         \x20   </Principal>\r\n\
         \x20 </Principals>\r\n\
         \x20 <Settings>\r\n\
         \x20   <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n\
         \x20   <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n\
         \x20   <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n\
         \x20   <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n\
         \x20   <Priority>5</Priority>\r\n\
         \x20   <Enabled>true</Enabled>\r\n\
         \x20 </Settings>\r\n\
         \x20 <Actions Context=\"Author\">\r\n\
         \x20   <Exec>\r\n\
         \x20     <Command>{conhost}</Command>\r\n\
         \x20     <Arguments>{arguments}</Arguments>\r\n\
         \x20   </Exec>\r\n\
         \x20 </Actions>\r\n\
         </Task>\r\n",
        user = escape(user_sid),
        documentation = spec
            .lpm_home
            .to_str()
            .map_or_else(String::new, |home| format!(
                "\x20   <Documentation>{WINDOWS_TASK_HOME_LABEL}{}</Documentation>\r\n",
                hex::encode(home)
            )),
        conhost = escape(&system_dir.join("conhost.exe").display().to_string()),
        arguments = escape(&arguments),
    )
}

/// The LPM home a logon task's definition, as `schtasks /Query /XML` prints
/// it, says it runs the proxy with: in the console's code page, which may
/// not hold the home's characters, or in UTF-16.
#[cfg(any(test, windows))]
pub(super) fn windows_task_home(definition: &[u8]) -> Option<std::path::PathBuf> {
    let utf16 = definition
        .strip_prefix(&[0xFF, 0xFE])
        .or_else(|| (definition.get(1) == Some(&0)).then_some(definition));
    let text = match utf16 {
        Some(utf16) => String::from_utf16_lossy(
            &utf16
                .as_chunks::<2>()
                .0
                .iter()
                .map(|unit| u16::from_le_bytes(*unit))
                .collect::<Vec<_>>(),
        ),
        None => String::from_utf8_lossy(definition).into_owned(),
    };
    let documentation = text.split_once("<Documentation>")?.1;
    let documentation = documentation.split_once("</Documentation>")?.0;
    let encoded = documentation.trim().strip_prefix(WINDOWS_TASK_HOME_LABEL)?;
    let home = String::from_utf8(hex::decode(encoded.trim()).ok()?).ok()?;
    Some(std::path::PathBuf::from(home))
}

/// The LPM home the installed logon task `task` runs the proxy with, where
/// its definition says.
#[cfg(windows)]
fn windows_installed_task_home(program: &Path, task: &str) -> Option<std::path::PathBuf> {
    let definition =
        run_checked_output(Command::new(program).args(["/Query", "/XML", "/TN", task])).ok()?;
    windows_task_home(&definition.stdout)
}

/// Writes `xml` as Task Scheduler reads it: UTF-16 with a byte order mark.
#[cfg(windows)]
fn write_windows_task_xml(path: &Path, xml: &str) -> Result<(), LpmError> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in xml.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    std::fs::write(path, bytes).map_err(LpmError::Io)
}

#[cfg(windows)]
fn windows_user_sid() -> Result<String, LpmError> {
    lpm_sandbox::helper_appcontainer::setup::current_user_sid().map_err(|error| {
        LpmError::Proxy(format!(
            "couldn't read this Windows user's identity: {error}"
        ))
    })
}

/// `spec` with the paths the task runs lpm with as it hands them on: without
/// a `\\?\` prefix where that names the same file, and with no `%`, which
/// Task Scheduler would read as part of an environment variable.
#[cfg(windows)]
fn windows_plain_spec(spec: &ProxyServiceSpec) -> Result<ProxyServiceSpec, LpmError> {
    let plain = |path: &Path| -> Result<std::path::PathBuf, LpmError> {
        let text = path.to_string_lossy();
        let path = match text.strip_prefix(r"\\?\") {
            Some(rest)
                if rest.as_bytes().get(1) == Some(&b':')
                    && std::path::absolute(rest)
                        .is_ok_and(|absolute| absolute == Path::new(rest)) =>
            {
                std::path::PathBuf::from(rest)
            }
            _ => path.to_path_buf(),
        };
        if path.to_string_lossy().contains('%') {
            return Err(LpmError::Proxy(format!(
                "can't start the proxy at sign-in through {}: Task Scheduler would read the `%` \
                 in it as part of an environment variable",
                path.display()
            )));
        }
        Ok(path)
    };
    Ok(ProxyServiceSpec {
        exe: plain(&spec.exe)?,
        working_dir: plain(&spec.working_dir)?,
        lpm_home: plain(&spec.lpm_home)?,
        stdout_log: plain(&spec.stdout_log)?,
        stderr_log: plain(&spec.stderr_log)?,
        ..spec.clone()
    })
}

#[cfg(any(test, windows))]
pub(super) fn quote_windows_command(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(test, windows))]
pub(super) fn quote_windows_arg(arg: &str) -> String {
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

pub(super) fn run_checked(command: &mut Command) -> Result<(), LpmError> {
    run_checked_output(command).map(|_| ())
}

pub(super) fn run_checked_output(command: &mut Command) -> Result<std::process::Output, LpmError> {
    let output = command
        .stdin(std::process::Stdio::inherit())
        .output()
        .map_err(LpmError::Io)?;
    if output.status.success() {
        return Ok(output);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(LpmError::Proxy(format!(
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
pub(super) fn run_checked_inherited(command: &mut Command) -> Result<(), LpmError> {
    run_checked_status(command.stdout(std::process::Stdio::from(std::io::stderr())))
}

/// Run `command` with the standard streams it was given, failing unless it
/// succeeds.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn run_checked_status(command: &mut Command) -> Result<(), LpmError> {
    let status = command.status().map_err(LpmError::Io)?;
    require_success(command, status)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn require_success(
    command: &Command,
    status: std::process::ExitStatus,
) -> Result<(), LpmError> {
    if status.success() {
        return Ok(());
    }
    Err(LpmError::Proxy(format!(
        "`{}` failed with {status}",
        format_command_for_error(command),
    )))
}

pub(super) fn format_command_for_error(command: &Command) -> String {
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
pub(super) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn systemd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn systemd_command(exe: &Path, args: &[String]) -> String {
    std::iter::once(exe.display().to_string())
        .chain(args.iter().cloned())
        .map(|arg| systemd_quote(&arg))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn systemd_path_value(path: &Path) -> String {
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

#[cfg(any(target_os = "linux", all(test, unix)))]
fn install_linux_forwarder_unit(program: &Path, unit: &str) -> Result<(), LpmError> {
    let systemctl = |args: &[&str]| {
        let mut command = Command::new(program);
        command
            .env("PATH", crate::elevation::ROOT_COMMAND_PATH)
            .arg("systemctl")
            .args(args);
        command
    };
    run_checked_inherited(&mut systemctl(&["daemon-reload"]))?;
    run_checked_inherited(&mut systemctl(&["enable", unit]))?;
    run_checked_inherited(&mut systemctl(&["restart", unit]))?;
    Ok(())
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn install_linux_user_unit(program: &Path, unit: &str) -> Result<(), LpmError> {
    run_checked(Command::new(program).args(["--user", "daemon-reload"]))?;
    run_checked(Command::new(program).args(["--user", "enable", unit]))?;
    run_checked(Command::new(program).args(["--user", "restart", unit]))?;
    Ok(())
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn uninstall_linux_user_unit(program: &Path, unit: &str) -> Result<(), LpmError> {
    let state = run_checked_output(Command::new(program).args([
        "--user",
        "show",
        "--property=LoadState",
        "--value",
        unit,
    ]))?;
    if String::from_utf8_lossy(&state.stdout).trim() == "not-found" {
        return Ok(());
    }
    run_checked(Command::new(program).args(["--user", "disable", "--now", unit]))
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn uninstall_macos_user_agent(program: &Path, target: &str) -> Result<(), LpmError> {
    run_macos_bootout(Command::new(program).args(["bootout", target]))
}

/// Registers `task` from the definition in `task_file`, replacing and
/// stopping one already there, and starts it.
#[cfg(any(windows, all(test, unix)))]
fn install_windows_user_task(program: &Path, task: &str, task_file: &Path) -> Result<(), LpmError> {
    if windows_user_task_exists(program, task)? {
        run_checked(Command::new(program).args(["/End", "/TN", task]))?;
    }
    run_checked(
        Command::new(program)
            .arg("/Create")
            .arg("/TN")
            .arg(task)
            .arg("/XML")
            .arg(task_file)
            .arg("/F"),
    )?;
    run_checked(Command::new(program).arg("/Run").arg("/TN").arg(task))?;
    Ok(())
}

#[cfg(any(windows, all(test, unix)))]
fn windows_user_task_exists(program: &Path, task: &str) -> Result<bool, LpmError> {
    let tasks = run_checked_output(Command::new(program).args(["/Query", "/FO", "CSV", "/NH"]))?;
    Ok(String::from_utf8_lossy(&tasks.stdout).lines().any(|line| {
        line.split(',').next().is_some_and(|name| {
            name.trim()
                .trim_matches('"')
                .trim_start_matches('\\')
                .eq_ignore_ascii_case(task.trim_start_matches('\\'))
        })
    }))
}

/// Stops and removes `task`, and says whether there was one.
#[cfg(any(windows, all(test, unix)))]
fn uninstall_windows_user_task(program: &Path, task: &str) -> Result<bool, LpmError> {
    if !windows_user_task_exists(program, task)? {
        return Ok(false);
    }
    run_checked(Command::new(program).args(["/End", "/TN", task]))?;
    run_checked(Command::new(program).args(["/Delete", "/TN", task, "/F"]))?;
    Ok(true)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn run_macos_bootout(command: &mut Command) -> Result<(), LpmError> {
    let output = command
        .stdin(std::process::Stdio::inherit())
        .output()
        .map_err(LpmError::Io)?;
    if output.status.success() || output.status.code() == Some(3) {
        return Ok(());
    }
    Err(LpmError::Proxy(format!(
        "`{}` failed with {}: {}",
        format_command_for_error(command),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(all(test, unix))]
mod service_execution_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture_program(directory: &Path, script: &str) -> PathBuf {
        let path = directory.join("manager");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn linux_reinstall_restarts_the_running_service_with_new_listeners() {
        let dir = tempfile::tempdir().unwrap();
        let program = fixture_program(
            dir.path(),
            r#"
case "$*" in
  *restart*) cp "$0.desired" "$0.running" ;;
  *enable*) if [ ! -f "$0.running" ]; then cp "$0.desired" "$0.running"; fi ;;
esac
exit 0
"#,
        );
        std::fs::write(program.with_extension("running"), "old listeners").unwrap();
        std::fs::write(program.with_extension("desired"), "new listeners").unwrap();
        install_linux_user_unit(&program, "dev.lpm.proxy.service").unwrap();
        assert_eq!(
            std::fs::read_to_string(program.with_extension("running")).unwrap(),
            "new listeners"
        );
    }

    #[test]
    fn linux_reinstall_restarts_the_forwarder_with_new_backend_targets() {
        let dir = tempfile::tempdir().unwrap();
        let program = fixture_program(
            dir.path(),
            r#"
case "$*" in
  *restart*) cp "$0.desired" "$0.running" ;;
  *enable*) if [ ! -f "$0.running" ]; then cp "$0.desired" "$0.running"; fi ;;
esac
exit 0
"#,
        );
        std::fs::write(program.with_extension("running"), "9443").unwrap();
        std::fs::write(program.with_extension("desired"), "9444").unwrap();
        install_linux_forwarder_unit(&program, "dev.lpm.proxy.forwarder.service").unwrap();
        assert_eq!(
            std::fs::read_to_string(program.with_extension("running")).unwrap(),
            "9444"
        );
    }

    #[test]
    fn windows_reinstall_replaces_the_running_task_with_new_listeners() {
        let dir = tempfile::tempdir().unwrap();
        let program = fixture_program(
            dir.path(),
            r#"
case "$1" in
  /Query) printf '%s\n' '"\LPM\Proxy","Running"' ;;
  /End) rm -f "$0.running" ;;
  /Create) cp "$0.desired" "$0.registered" ;;
  /Run) if [ ! -f "$0.running" ]; then cp "$0.registered" "$0.running"; fi ;;
esac
exit 0
"#,
        );
        std::fs::write(program.with_extension("running"), "old listeners").unwrap();
        std::fs::write(program.with_extension("desired"), "new listeners").unwrap();
        install_windows_user_task(&program, r"\LPM\Proxy", Path::new("proxy.cmd")).unwrap();
        assert_eq!(
            std::fs::read_to_string(program.with_extension("running")).unwrap(),
            "new listeners"
        );
    }

    #[test]
    fn windows_reinstall_preserves_the_registered_task_when_stop_fails() {
        let dir = tempfile::tempdir().unwrap();
        let program = fixture_program(
            dir.path(),
            r#"
case "$1" in
  /Query) printf '%s\n' '"\LPM\Proxy","Running"' ;;
  /End) echo denied >&2; exit 5 ;;
  /Create) touch "$0.replaced" ;;
esac
exit 0
"#,
        );
        assert!(
            install_windows_user_task(&program, r"\LPM\Proxy", Path::new("proxy.cmd")).is_err()
        );
        assert!(!program.with_extension("replaced").exists());
    }

    #[test]
    fn windows_task_lookup_matches_the_complete_task_path() {
        let dir = tempfile::tempdir().unwrap();
        let program = fixture_program(
            dir.path(),
            r#"
printf '%s\n' '"\Other\LPM\Proxy","Ready"' '"\LPM\Proxy-old","Ready"' '"\Other","\LPM\Proxy"'
"#,
        );
        assert!(!windows_user_task_exists(&program, r"\LPM\Proxy").unwrap());
        let program = fixture_program(dir.path(), r#"printf '%s\n' '"\lpm\proxy","Ready"'"#);
        assert!(windows_user_task_exists(&program, r"\LPM\Proxy").unwrap());
    }

    #[test]
    fn uninstall_propagates_service_manager_failures() {
        let dir = tempfile::tempdir().unwrap();
        let program = fixture_program(dir.path(), "echo 'manager access denied' >&2; exit 5");
        assert!(uninstall_macos_user_agent(&program, "gui/501/dev.lpm.proxy").is_err());
        assert!(uninstall_windows_user_task(&program, r"\LPM\Proxy").is_err());
        assert!(uninstall_linux_user_unit(&program, "dev.lpm.proxy.service").is_err());
    }

    #[test]
    fn absent_services_can_be_uninstalled_again() {
        let dir = tempfile::tempdir().unwrap();
        let program = fixture_program(dir.path(), "exit 3");
        uninstall_macos_user_agent(&program, "gui/501/dev.lpm.proxy").unwrap();
        let program = fixture_program(dir.path(), "echo not-found; exit 0");
        uninstall_linux_user_unit(&program, "dev.lpm.proxy.service").unwrap();
        let program = fixture_program(dir.path(), "exit 0");
        uninstall_windows_user_task(&program, r"\LPM\Proxy").unwrap();
    }

    #[test]
    fn windows_uninstall_keeps_manager_progress_off_stdout() {
        const CHILD: &str = "LPM_PROXY_MANAGER_STDIO_CHILD";
        const MARKER: &str = "task-manager-progress";
        if std::env::var_os(CHILD).is_some() {
            let dir = tempfile::tempdir().unwrap();
            let program = fixture_program(
                dir.path(),
                &format!(
                    r#"
case "$1" in
  /Query) printf '"\\LPM\\Proxy","Ready"\n' ;;
  *) echo {MARKER}; printf '%s\n' "$1" >> "$0.calls" ;;
esac
exit 0
"#
                ),
            );
            uninstall_windows_user_task(&program, r"\LPM\Proxy").unwrap();
            assert_eq!(
                std::fs::read_to_string(program.with_extension("calls")).unwrap(),
                "/End\n/Delete\n"
            );
            return;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "commands::proxy::proxy_platform::service_execution_tests::windows_uninstall_keeps_manager_progress_off_stdout", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(MARKER));
    }
}

#[cfg(all(test, windows))]
mod windows_task_tests {
    use super::*;

    /// Task Scheduler takes the logon task from a user who isn't elevated,
    /// as a trigger for this user's logon alone needs no administrator, and
    /// gives back the home it runs the proxy with, past ASCII too.
    #[test]
    fn the_logon_task_registers_for_this_user_and_is_removed_again() {
        struct DeleteTask(String);
        impl Drop for DeleteTask {
            fn drop(&mut self) {
                let _ = Command::new("schtasks")
                    .args(["/Delete", "/TN", &self.0, "/F"])
                    .output();
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("Çağrı home");
        let service_dir = lpm_home.join("services").join("proxy");
        let spec = ProxyServiceSpec {
            label: "dev.lpm.proxy",
            exe: dir.path().join("lpm.exe"),
            working_dir: dir.path().to_path_buf(),
            lpm_home,
            start_args: vec!["proxy".into(), "start".into()],
            launcher_path: service_dir.join("start-proxy.cmd"),
            stdout_log: service_dir.join("proxy.out.log"),
            stderr_log: service_dir.join("proxy.err.log"),
        };
        let user = windows_user_sid().unwrap();
        let system = lpm_common::platform::windows_system_directory().unwrap();
        let task_file = dir.path().join("proxy-task.xml");
        write_windows_task_xml(&task_file, &render_windows_task_xml(&spec, &user, &system))
            .unwrap();
        let task = format!(r"\LPM Proxy test {}", std::process::id());
        let schtasks = Path::new("schtasks");

        run_checked(
            Command::new(schtasks)
                .arg("/Create")
                .arg("/TN")
                .arg(&task)
                .arg("/XML")
                .arg(&task_file)
                .arg("/F"),
        )
        .unwrap();
        let _delete = DeleteTask(task.clone());

        assert!(windows_user_task_exists(schtasks, &task).unwrap());
        assert_eq!(
            windows_installed_task_home(schtasks, &task).as_ref(),
            Some(&spec.lpm_home)
        );
        assert!(uninstall_windows_user_task(schtasks, &task).unwrap());
        assert!(!windows_user_task_exists(schtasks, &task).unwrap());
        assert!(!uninstall_windows_user_task(schtasks, &task).unwrap());
    }
}
