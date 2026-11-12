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

/// cmd.exe reads a batch file in the console's code page, so the launcher
/// holds no path: it finds LPM's home from its own place in it and gets lpm
/// and the project as arguments.
#[test]
fn windows_launcher_holds_no_path() {
    let mut spec = sample_service_spec();
    spec.lpm_home = PathBuf::from("/tmp/Çağrı/.lpm");
    spec.launcher_path = spec.lpm_home.join("services/proxy/start-proxy.cmd");
    spec.stdout_log = spec.lpm_home.join("services/proxy/proxy.out.log");
    spec.stderr_log = spec.lpm_home.join("services/proxy/proxy.err.log");

    let launcher = render_windows_launcher(&spec);

    assert!(launcher.is_ascii(), "{launcher}");
    assert!(launcher.starts_with(lpm_common::symlink::WINDOWS_CMD_SHIM_PREAMBLE));
    assert!(launcher.contains(r#"@FOR %%I IN ("%dp0%..\..") DO @SET "LPM_HOME=%%~fI""#));
    assert!(launcher.contains("@CD /D \"%~2\" || EXIT /B 1\r\n"));
    assert!(launcher.contains(
        r#"@"%~1" proxy start --tls-port 9443 >>"%dp0%proxy.out.log" 2>>"%dp0%proxy.err.log""#
    ));
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
        "conhost.exe</Command>",
        "<Arguments>--headless &quot;",
        r"Çağrı\R&amp;D &lt;bin&gt;\lpm.exe",
    ] {
        assert!(xml.contains(element), "{element}: {xml}");
    }
    assert!(!xml.contains("R&D <bin>"), "{xml}");
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
