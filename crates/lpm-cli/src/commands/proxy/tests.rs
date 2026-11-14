use super::proxy_platform::*;
use super::proxy_service::*;
use super::*;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};

#[test]
fn resolve_start_options_rejects_oversized_project_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lpm.json");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1)
        .unwrap();

    let error = resolve_start_options(dir.path(), None, None, None).unwrap_err();

    let message = error.to_string();
    assert!(
        message.contains(&path.display().to_string()) && message.contains("16777216-byte limit"),
        "error must identify proxy config and limit: {message}"
    );
}

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
            public_tls_port: None,
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
            public_tls_port: None,
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
            public_tls_port: None,
            http_port: Some(8080),
            http_redirect_port: None,
            tls_port: None,
        }
    );
}

#[test]
fn proxy_service_start_args_use_resolved_listener_options() {
    let args = listener_args(lpm_proxy::ProxyDaemonOptions {
        public_tls_port: None,
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
        public_tls_port: None,
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
        public_tls_port: None,
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
            public_tls_port: None,
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
            public_tls_port: None,
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
            public_tls_port: None,
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
            public_tls_port: None,
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
            public_tls_port: None,
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
            public_tls_port: None,
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
        public_tls_port: None,
        http_port: None,
        http_redirect_port: None,
        tls_port: Some(9443),
    })
    .unwrap_err();

    assert!(err.to_string().contains("does not need"), "got {err}");
}

#[test]
fn privileged_forwarder_config_maps_low_listeners_to_user_daemon_listeners() {
    let config = PrivilegedForwarderConfig::new(
        501,
        PathBuf::from("/tmp/lpm home/proxy.json"),
        PathBuf::from("/tmp/LPM Bin/lpm-rs"),
        lpm_proxy::ProxyDaemonOptions {
            public_tls_port: None,
            http_port: None,
            http_redirect_port: Some(80),
            tls_port: Some(443),
        },
    )
    .unwrap();

    assert_eq!(
        config
            .rules
            .iter()
            .map(|rule| (rule.target, rule.listen_addr))
            .collect::<Vec<_>>(),
        vec![
            (lpm_proxy::ForwarderTarget::Https, loopback_socket_addr(443)),
            (
                lpm_proxy::ForwarderTarget::HttpRedirect,
                loopback_socket_addr(80)
            ),
        ]
    );
}

#[test]
fn privileged_forwarder_config_stays_readable_by_releases_that_pinned_the_backend() {
    let config = PrivilegedForwarderConfig::new(
        501,
        PathBuf::from("/tmp/lpm home/proxy.json"),
        PathBuf::from("/tmp/LPM Bin/lpm-rs"),
        lpm_proxy::ProxyDaemonOptions {
            public_tls_port: None,
            http_port: None,
            http_redirect_port: Some(80),
            tls_port: Some(443),
        },
    )
    .unwrap();

    assert_eq!(
        serde_json::to_value(&config.rules).unwrap(),
        serde_json::json!([
            {"name": "https", "listenAddr": "127.0.0.1:443", "targetAddr": "127.0.0.1:9443"},
            {"name": "httpRedirect", "listenAddr": "127.0.0.1:80", "targetAddr": "127.0.0.1:9080"},
        ])
    );
}

#[test]
fn privileged_forwarder_reads_configs_that_pinned_a_backend_address() {
    let config: PrivilegedForwarderConfig = serde_json::from_value(serde_json::json!({
        "targetUid": 501,
        "statePath": "/tmp/lpm home/proxy.json",
        "binaryPath": "/tmp/LPM Bin/lpm-rs",
        "rules": [
            {"name": "https", "listenAddr": "127.0.0.1:443", "targetAddr": "127.0.0.1:9444"},
            {"name": "httpRedirect", "listenAddr": "127.0.0.1:80", "targetAddr": "127.0.0.1:9081"},
        ],
    }))
    .unwrap();

    assert_eq!(
        config
            .rules
            .iter()
            .map(|rule| (rule.target, rule.listen_addr))
            .collect::<Vec<_>>(),
        vec![
            (lpm_proxy::ForwarderTarget::Https, loopback_socket_addr(443)),
            (
                lpm_proxy::ForwarderTarget::HttpRedirect,
                loopback_socket_addr(80)
            ),
        ]
    );
}

#[test]
fn listener_announcement_names_a_free_port_instead_of_port_zero() {
    assert_eq!(
        listener_announcement("HTTPS", 0),
        "HTTPS on a free 127.0.0.1 port"
    );
    assert_eq!(
        listener_announcement("HTTP redirect", 9080),
        "HTTP redirect on 127.0.0.1:9080"
    );
}

#[test]
fn privileged_backend_options_bind_free_ports_behind_the_public_listeners() {
    let backend = privileged_backend_options(lpm_proxy::ProxyDaemonOptions {
        public_tls_port: None,
        http_port: None,
        http_redirect_port: Some(80),
        tls_port: Some(443),
    });

    assert_eq!(
        backend,
        lpm_proxy::ProxyDaemonOptions {
            public_tls_port: Some(443),
            http_port: None,
            http_redirect_port: Some(0),
            tls_port: Some(0),
        }
    );
    assert_eq!(
        listener_args(backend),
        vec![
            "--public-tls-port",
            "443",
            "--tls-port",
            "0",
            "--http-redirect-port",
            "0"
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

    let err = reject_conflicting_privileged_forwarder_owner(&config_path, 502, false).unwrap_err();

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
    let message =
        format_privileged_forwarder_cleanup_error(&LpmError::Proxy("sudo failed".into()), &spec);

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

/// The logon task has conhost run lpm itself, which gets the home, project
/// and logs as arguments, and the proxy's command after `--`.
#[test]
fn windows_task_runs_lpm_with_the_home_project_and_logs() {
    let spec = sample_service_spec();

    assert_eq!(
        windows_task_command(&spec),
        [
            "/tmp/LPM Bin/lpm-rs",
            "internal-proxy-service",
            "--home",
            "/tmp/lpm home",
            "--project",
            "/tmp/project dir",
            "--stdout",
            "/tmp/lpm home/services/proxy/proxy.out.log",
            "--stderr",
            "/tmp/lpm home/services/proxy/proxy.err.log",
            "--",
            "proxy",
            "start",
            "--tls-port",
            "9443",
        ]
    );
}

/// conhost splits its command line into arguments and joins
/// them again, quoting only those with a space in them, and the cmd.exe
/// command line the task used to give it came out in pieces. lpm's
/// arguments come out as they went in.
#[cfg(windows)]
#[test]
fn the_windows_task_command_survives_conhost_joining_it_again() {
    let mut spec = sample_service_spec();
    spec.exe = PathBuf::from(r"C:\Program Files\LPM\lpm.exe");
    spec.lpm_home = PathBuf::from(r"C:\Users\John Smith & Çağrı\.lpm");
    spec.working_dir = PathBuf::from(r"D:\R&D (p q)\app ^!x!");
    spec.stdout_log = spec.lpm_home.join(r"services\proxy\proxy.out.log");
    spec.stderr_log = spec.lpm_home.join(r"services\proxy\proxy.err.log");
    let command = windows_task_command(&spec);

    let arguments = command_line_arguments(&quote_windows_command(&command));
    assert_eq!(arguments, command);
    let joined_again = arguments
        .iter()
        .map(|argument| {
            if argument.contains(' ') {
                format!("\"{argument}\"")
            } else {
                argument.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(command_line_arguments(&joined_again), command);
}

/// The arguments a program started with `command_line` reads.
#[cfg(windows)]
fn command_line_arguments(command_line: &str) -> Vec<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

    // The first word is the program's name, which is read by other rules.
    let wide = format!("program {command_line}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut count = 0;
    // SAFETY: `wide` is NUL-terminated; the result is freed below.
    let argv = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    assert!(!argv.is_null());
    let arguments = (1..usize::try_from(count).unwrap())
        .map(|index| {
            // SAFETY: CommandLineToArgvW returned `count` NUL-terminated strings.
            let argument = unsafe { *argv.add(index) };
            let length = (0..)
                .take_while(|offset| unsafe { *argument.add(*offset) } != 0)
                .count();
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(argument, length) })
        })
        .collect();
    // SAFETY: the array came from CommandLineToArgvW and is freed once.
    unsafe { LocalFree(argv.cast()) };
    arguments
}

/// node.exe on `PATH`, which stands in for lpm.
#[cfg(windows)]
fn node_on_path() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("node.exe"))
        .find(|node| node.is_file())
}

/// As the sign-in task runs it, under a home and a project whose paths hold
/// spaces, `&` and what no code page holds, lpm's proxy starts in the
/// project with that home and its output in the logs. node stands in for
/// lpm: it runs the script `proxy` in the project, which records what it got
/// and keeps running.
#[cfg(windows)]
#[test]
fn the_sign_in_task_starts_the_proxy_in_the_project_with_its_home() {
    let Some(node) = node_on_path() else {
        eprintln!("skipped: no node.exe on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("Çağrı home & co");
    let project = dir.path().join("R&D Çağrı (p q)");
    std::fs::create_dir_all(&project).unwrap();
    let record = dir.path().join("record.json");
    std::fs::write(
        project.join("proxy"),
        format!(
            "require('fs').writeFileSync({:?}, JSON.stringify({{home: process.env.LPM_HOME, \
             cwd: process.cwd(), args: process.argv.slice(2)}}));\n\
             console.log('listening'); console.error('warming up');\n\
             setTimeout(() => {{}}, 2000);\n",
            record.display().to_string()
        ),
    )
    .unwrap();
    let out = dir.path().join("proxy.out.log");
    let err = dir.path().join("proxy.err.log");
    let args: Vec<std::ffi::OsString> = ["proxy", "start", "--tls-port", "9443"]
        .into_iter()
        .map(Into::into)
        .collect();

    start_proxy_service(
        &node,
        &home,
        &project,
        std::fs::File::create(&out).unwrap(),
        &std::fs::File::create(&err).unwrap(),
        &args,
        Duration::from_millis(1500),
    )
    .unwrap();

    // node may take longer than the start's wait to get going, as in a
    // parallel test run.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let written = |path: &Path| std::fs::read_to_string(path).is_ok_and(|text| !text.is_empty());
    while !(written(&record) && written(&out) && written(&err)) {
        assert!(
            std::time::Instant::now() < deadline,
            "node wrote no record and logs"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let recorded: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    assert_eq!(recorded["home"], home.display().to_string(), "{recorded}");
    assert_eq!(
        std::fs::canonicalize(recorded["cwd"].as_str().unwrap()).unwrap(),
        std::fs::canonicalize(&project).unwrap()
    );
    assert_eq!(
        recorded["args"],
        serde_json::json!(["start", "--tls-port", "9443"])
    );
    assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "listening");
    assert_eq!(std::fs::read_to_string(&err).unwrap().trim(), "warming up");
    // node runs on for two seconds in the project, which can't be removed
    // until it ends.
    let dir = dir.keep();
    while std::fs::remove_dir_all(&dir).is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "node kept {} in use",
            dir.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A proxy that exits at once, as one whose ports are taken does, or a
/// project that is gone, fails the start, which is logged; one stopped
/// at once, which ends well, doesn't.
#[cfg(windows)]
#[test]
fn a_sign_in_start_that_fails_says_so() {
    let Some(node) = node_on_path() else {
        eprintln!("skipped: no node.exe on PATH");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("proxy"), "process.exit(3);\n").unwrap();
    let log = || std::fs::File::create(dir.path().join("log")).unwrap();
    let args = [std::ffi::OsString::from("proxy")];

    let exited = start_proxy_service(
        &node,
        dir.path(),
        dir.path(),
        log(),
        &log(),
        &args,
        Duration::from_secs(10),
    )
    .unwrap_err();
    assert!(
        exited.to_string().contains("exited (exit code: 3)"),
        "{exited}"
    );

    std::fs::write(dir.path().join("proxy"), "process.exit(0);\n").unwrap();
    start_proxy_service(
        &node,
        dir.path(),
        dir.path(),
        log(),
        &log(),
        &args,
        Duration::from_secs(10),
    )
    .unwrap();

    let gone = start_proxy_service(
        &node,
        dir.path(),
        &dir.path().join("gone"),
        log(),
        &log(),
        &args,
        Duration::from_secs(10),
    )
    .unwrap_err();
    assert!(gone.to_string().contains("isn't there"), "{gone}");
}

/// The logon task is this user's own, needs no administrator, runs in no
/// window and for as long as the user is signed in; the paths, in the
/// UTF-16 definition, can be anything.
#[test]
fn windows_logon_task_is_the_users_own_and_runs_hidden() {
    let mut spec = sample_service_spec();
    spec.exe = PathBuf::from(r"C:\Users\Çağrı\R&D <bin>\lpm.exe");

    let xml = render_windows_task_xml(
        &spec,
        "S-1-5-21-1-2-3-1001",
        Path::new(r"C:\Windows\System32"),
    );

    assert_eq!(
        xml.matches("<UserId>S-1-5-21-1-2-3-1001</UserId>").count(),
        2
    );
    for element in [
        "<LogonType>InteractiveToken</LogonType>",
        "<RunLevel>LeastPrivilege</RunLevel>",
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
        "<Priority>5</Priority>",
        "conhost.exe</Command>",
        r"<Arguments>--headless &quot;C:\Users\Çağrı\R&amp;D &lt;bin&gt;\lpm.exe&quot; internal-proxy-service --home ",
    ] {
        assert!(xml.contains(element), "{element}: {xml}");
    }
    assert!(!xml.contains("R&D <bin>"), "{xml}");
}

/// Uninstall and reinstall stop the proxy the task started, with the home
/// it gives it, whatever `LPM_HOME` they run with; and schtasks prints the
/// definition in the console's code page, which may not hold the home.
#[test]
fn the_logon_task_says_which_home_it_runs_the_proxy_with() {
    let mut spec = sample_service_spec();
    spec.lpm_home = PathBuf::from(r"C:\Users\Çağrı\home B & <co>\");
    let xml = render_windows_task_xml(
        &spec,
        "S-1-5-21-1-2-3-1001",
        Path::new(r"C:\Windows\System32"),
    );

    assert_eq!(
        windows_task_home(xml.as_bytes()),
        Some(spec.lpm_home.clone())
    );
    let in_a_code_page = xml
        .chars()
        .map(|character| if character.is_ascii() { character } else { '?' })
        .collect::<String>();
    assert_eq!(
        windows_task_home(in_a_code_page.as_bytes()),
        Some(spec.lpm_home.clone())
    );
    let utf16 = xml
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(windows_task_home(&utf16), Some(spec.lpm_home.clone()));
    let with_mark = [0xFF, 0xFE].into_iter().chain(utf16).collect::<Vec<_>>();
    assert_eq!(windows_task_home(&with_mark), Some(spec.lpm_home));
    assert_eq!(windows_task_home(b"<Task><RegistrationInfo/></Task>"), None);
}

/// Uninstall stops the proxy an earlier release's task started with its own
/// home, read from the batch file that task ran. schtasks prints the path
/// with XML's references, `&amp;` for `&`, in UTF-16 or the console's code
/// page.
#[test]
fn the_earlier_task_names_its_home_by_its_batch_file() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("R&D's earlier home");
    std::fs::create_dir(&home).unwrap();
    let definition = |command: &Path| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
             <Task><Actions><Exec><Command>\"{}\"</Command></Exec></Actions></Task>",
            command.display().to_string().replace('&', "&amp;")
        )
    };

    let launcher = definition(&windows_earlier_launcher(&home));
    assert_eq!(
        windows_earlier_task_home_from(launcher.as_bytes()),
        Some(home.clone())
    );
    let utf16 = [0xFF, 0xFE]
        .into_iter()
        .chain(launcher.encode_utf16().flat_map(u16::to_le_bytes))
        .collect::<Vec<_>>();
    assert_eq!(windows_earlier_task_home_from(&utf16), Some(home.clone()));
    assert_eq!(
        windows_earlier_task_home_from(definition(&home.join("start-proxy.cmd")).as_bytes()),
        None
    );
    let gone = dir.path().join("gone");
    assert_eq!(
        windows_earlier_task_home_from(definition(&windows_earlier_launcher(&gone)).as_bytes()),
        None
    );
    assert_eq!(windows_earlier_task_home_from(b"<Task></Task>"), None);
    assert_eq!(windows_earlier_task_home_from(b"<Command>unclosed"), None);
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
    let external_options = lpm_proxy::ProxyDaemonOptions {
        public_tls_port: None,
        http_port: None,
        http_redirect_port: Some(80),
        tls_port: Some(443),
    };
    let backend_options = privileged_backend_options(external_options);
    let config = PrivilegedForwarderConfig::new(
        501,
        PathBuf::from("/tmp/lpm home/proxy.json"),
        PathBuf::from("/tmp/LPM Bin/lpm-rs"),
        external_options,
    )
    .unwrap();
    PrivilegedForwarderSpec {
        label: "dev.lpm.proxy.forwarder",
        exe: PathBuf::from("/tmp/LPM Bin/lpm-rs"),
        executable: super::forwarder_executable::ForwarderExecutable::plan(
            Path::new("/home/dev/.lpm/bin/lpm-rs"),
            PathBuf::from("/tmp/LPM Bin"),
        ),
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
            public_tls_port: None,
            http_port: None,
            http_redirect_port: Some(80),
            tls_port: Some(443),
        },
    )
    .unwrap();
    std::fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
}

/// Stands in for `sudo`: runs each step as the current user after the shell
/// `prelude`, skipping `chown`, which needs root.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn fake_privileged_runner(directory: &Path, prelude: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(directory).unwrap();
    let path = directory.join("privileged");
    std::fs::write(
        &path,
        format!("#!/bin/sh\nif [ \"$1\" = chown ]; then exit 0; fi\n{prelude}exec \"$@\"\n"),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// A Job that refuses breakaway, as an `lpm dev` service's does, makes
/// CreateProcess fail with ACCESS_DENIED: the daemon then starts inside it
/// rather than not at all.
#[cfg(windows)]
#[test]
fn a_detached_daemon_a_job_keeps_still_starts() {
    let mut attempts = 0;
    let mut command = std::process::Command::new("cmd");
    command.args(["/d", "/c", "exit", "0"]);

    let mut daemon = spawn_detached_daemon_with(&mut command, |command| {
        attempts += 1;
        if attempts == 1 {
            Err(std::io::Error::from_raw_os_error(
                windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32,
            ))
        } else {
            command.spawn()
        }
    })
    .unwrap();

    assert_eq!(attempts, 2, "a refused breakaway is retried inside the Job");
    assert!(daemon.kept_in_job, "lpm says the Job keeps the daemon");
    assert!(daemon.child.wait().unwrap().success());
}

fn proxy_status_from(pid: u32) -> ProxyStatus {
    ProxyStatus {
        running: true,
        pid: Some(pid),
        http_addr: None,
        http_redirect_addr: None,
        tls_addr: None,
        public_tls_addr: None,
        routes: Vec::new(),
        stale: false,
        state_error: None,
    }
}

/// Another session's daemon may have taken the socket first, while lpm's
/// own is still on its way out: the proxy that is up is then that one,
/// which no Job of lpm's keeps.
#[test]
fn only_the_detached_daemon_that_is_up_is_said_to_run_in_the_job() {
    let mut idle = if cfg!(windows) {
        let mut idle = std::process::Command::new("ping");
        idle.args(["-n", "30", "127.0.0.1"]);
        idle
    } else {
        let mut idle = std::process::Command::new("sleep");
        idle.arg("30");
        idle
    };
    let mut daemon = DetachedDaemon {
        child: idle.stdout(Stdio::null()).spawn().unwrap(),
        kept_in_job: true,
    };
    let own = proxy_status_from(daemon.child.id());
    let another_session_s = proxy_status_from(std::process::id());

    let own_in_job = daemon.runs_in_job(&own);
    let another_in_job = daemon.runs_in_job(&another_session_s);
    daemon.kept_in_job = false;
    let own_outside_any_job = daemon.runs_in_job(&own);
    let _ = daemon.child.kill();
    let _ = daemon.child.wait();

    assert!(own_in_job);
    assert!(
        !another_in_job,
        "another session's daemon was said to be ours"
    );
    assert!(!own_outside_any_job);
}

#[cfg(windows)]
#[test]
fn a_detached_daemon_failing_for_another_reason_is_not_retried() {
    let mut attempts = 0;
    let mut command = std::process::Command::new("cmd");

    let error = spawn_detached_daemon_with(&mut command, |_| {
        attempts += 1;
        Err(std::io::Error::from_raw_os_error(2))
    })
    .err()
    .unwrap();

    assert_eq!(attempts, 1);
    assert_eq!(error.raw_os_error(), Some(2));
}
