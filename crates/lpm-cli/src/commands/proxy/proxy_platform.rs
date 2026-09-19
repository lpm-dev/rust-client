use super::proxy_service::{PrivilegedForwarderSpec, ProxyServiceSpec};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::proxy_service::{
    reject_conflicting_privileged_forwarder_owner, reject_removing_foreign_privileged_forwarder,
};
use lpm_common::LpmError;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
use std::process::Command;

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

#[cfg(target_os = "macos")]
pub(super) fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    let target = macos_launchctl_target(spec.label);
    uninstall_macos_user_agent(Path::new("launchctl"), &target)?;
    let plist_path = macos_launch_agent_path(spec.label)?;
    if plist_path.exists() {
        std::fs::remove_file(plist_path).map_err(LpmError::Io)?;
    }
    Ok(())
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

#[cfg(target_os = "linux")]
pub(super) fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    let unit_name = linux_systemd_unit_name(spec.label);
    uninstall_linux_user_unit(Path::new("systemctl"), &unit_name)?;
    let unit_path = linux_systemd_user_unit_path(spec.label)?;
    if unit_path.exists() {
        std::fs::remove_file(unit_path).map_err(LpmError::Io)?;
    }
    if spec.launcher_path.exists() {
        std::fs::remove_file(&spec.launcher_path).map_err(LpmError::Io)?;
    }
    run_checked(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    Ok(())
}

#[cfg(windows)]
pub(super) fn install_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    write_windows_launcher(spec)?;
    install_windows_user_task(
        Path::new("schtasks"),
        windows_task_name(spec.label),
        &spec.launcher_path,
    )?;
    Ok(())
}

#[cfg(windows)]
pub(super) fn uninstall_proxy_service_platform(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    uninstall_windows_user_task(Path::new("schtasks"), windows_task_name(spec.label))?;
    if spec.launcher_path.exists() {
        std::fs::remove_file(&spec.launcher_path).map_err(LpmError::Io)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub(super) fn install_proxy_service_platform(_spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    Err(LpmError::Script(
        "`lpm proxy install` is not supported on this platform".into(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub(super) fn uninstall_proxy_service_platform(_spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    Err(LpmError::Script(
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
    install_linux_forwarder_unit(Path::new("sudo"), &linux_systemd_unit_name(spec.label))?;
    let _ = std::fs::remove_file(config_source);
    let _ = std::fs::remove_file(unit_source);
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn uninstall_privileged_forwarder_platform(
    spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    reject_removing_foreign_privileged_forwarder(&spec.config_path, spec.config.target_uid)?;
    let unit = linux_systemd_unit_name(spec.label);
    let state = run_checked_output(Command::new("systemctl").args([
        "show",
        "--property=LoadState",
        "--value",
        &unit,
    ]))?;
    if String::from_utf8_lossy(&state.stdout).trim() != "not-found" {
        run_checked_inherited(Command::new("sudo").args(["systemctl", "disable", "--now", &unit]))?;
    }
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
    run_checked_inherited(Command::new("sudo").args(["systemctl", "daemon-reload"]))?;
    Ok(())
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
    run_macos_bootout(Command::new("sudo").args(["launchctl", "bootout", &target]))?;
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
pub(super) fn uninstall_privileged_forwarder_platform(
    spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    reject_removing_foreign_privileged_forwarder(&spec.config_path, spec.config.target_uid)?;
    let target = macos_system_launchctl_target(spec.label);
    run_macos_bootout(Command::new("sudo").args(["launchctl", "bootout", &target]))?;
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
pub(super) fn install_privileged_forwarder_platform(
    _spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    Err(LpmError::Script(
        "`lpm proxy install --privileged-ports` is only supported on Linux and macOS".into(),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn uninstall_privileged_forwarder_platform(
    _spec: &PrivilegedForwarderSpec,
) -> Result<(), LpmError> {
    Err(LpmError::Script(
        "`lpm proxy uninstall --privileged-ports` is only supported on Linux and macOS".into(),
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn write_privileged_staging_file(
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
pub(super) fn install_root_file(
    source: &Path,
    destination: &Path,
    mode: &str,
) -> Result<(), LpmError> {
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
pub(super) fn macos_launch_agent_path(label: &str) -> Result<PathBuf, LpmError> {
    let home = dirs::home_dir().ok_or_else(|| {
        LpmError::Script("could not determine home directory for LaunchAgent install".into())
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
            LpmError::Script("could not determine config directory for systemd user unit".into())
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

#[cfg(windows)]
pub(super) fn write_windows_launcher(spec: &ProxyServiceSpec) -> Result<(), LpmError> {
    if let Some(parent) = spec.launcher_path.parent() {
        std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
    }
    std::fs::write(&spec.launcher_path, render_windows_launcher(spec)).map_err(LpmError::Io)
}

#[cfg(any(test, windows))]
pub(super) fn render_windows_launcher(spec: &ProxyServiceSpec) -> String {
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
pub(super) fn windows_task_name(_label: &str) -> &'static str {
    r"\LPM\Proxy"
}

#[cfg(any(windows, all(test, unix)))]
pub(super) fn quote_windows_task_command(path: &Path) -> String {
    quote_windows_command(&[path.display().to_string()])
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

fn run_checked_output(command: &mut Command) -> Result<std::process::Output, LpmError> {
    let output = command
        .stdin(std::process::Stdio::inherit())
        .output()
        .map_err(LpmError::Io)?;
    if output.status.success() {
        return Ok(output);
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
pub(super) fn run_checked_inherited(command: &mut Command) -> Result<(), LpmError> {
    let status = command
        .stdout(std::process::Stdio::from(std::io::stderr()))
        .status()
        .map_err(LpmError::Io)?;
    if status.success() {
        return Ok(());
    }
    Err(LpmError::Script(format!(
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
    run_checked_inherited(Command::new(program).args(["systemctl", "daemon-reload"]))?;
    run_checked_inherited(Command::new(program).args(["systemctl", "enable", unit]))?;
    run_checked_inherited(Command::new(program).args(["systemctl", "restart", unit]))?;
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

#[cfg(any(windows, all(test, unix)))]
fn install_windows_user_task(program: &Path, task: &str, launcher: &Path) -> Result<(), LpmError> {
    if windows_user_task_exists(program, task)? {
        run_checked(Command::new(program).args(["/End", "/TN", task]))?;
    }
    run_checked(
        Command::new(program)
            .arg("/Create")
            .arg("/TN")
            .arg(task)
            .arg("/SC")
            .arg("ONLOGON")
            .arg("/TR")
            .arg(quote_windows_task_command(launcher))
            .arg("/RL")
            .arg("LIMITED")
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

#[cfg(any(windows, all(test, unix)))]
fn uninstall_windows_user_task(program: &Path, task: &str) -> Result<(), LpmError> {
    if !windows_user_task_exists(program, task)? {
        return Ok(());
    }
    run_checked(Command::new(program).args(["/End", "/TN", task]))?;
    run_checked(Command::new(program).args(["/Delete", "/TN", task, "/F"]))
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
    Err(LpmError::Script(format!(
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
