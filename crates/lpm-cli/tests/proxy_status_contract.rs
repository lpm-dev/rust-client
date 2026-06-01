//! CLI-binary tier justification: these tests pin direct subprocess stdout /
//! stderr separation and foreground process lifecycle for the new `lpm proxy`
//! surface. The workflow harness intentionally hides fd boundaries and
//! long-lived child-process control that are part of this contract.

mod common;

use std::process::Stdio;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tempfile::TempDir;

static PROXY_DAEMON_TEST_LOCK: Mutex<()> = Mutex::new(());

fn proxy_daemon_test_guard() -> MutexGuard<'static, ()> {
    PROXY_DAEMON_TEST_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

fn isolated_dirs() -> (TempDir, TempDir) {
    let project = TempDir::new().expect("create temp project");
    let lpm_home = TempDir::new().expect("create temp LPM_HOME");
    (project, lpm_home)
}

#[test]
fn proxy_status_json_reports_not_running_with_clean_stderr() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "status"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["running"], false);
    assert_eq!(json["pid"], serde_json::Value::Null);
    assert_eq!(json["httpAddr"], serde_json::Value::Null);
    assert_eq!(json["httpRedirectAddr"], serde_json::Value::Null);
    assert_eq!(json["tlsAddr"], serde_json::Value::Null);
    assert_eq!(json["routes"], serde_json::json!([]));
    assert_eq!(json["stale"], false);
    assert_eq!(json["stateError"], serde_json::Value::Null);
}

#[test]
fn proxy_list_json_reports_empty_routes_with_clean_stderr() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "list"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["running"], false);
    assert_eq!(json["routes"], serde_json::json!([]));
}

#[test]
fn proxy_status_human_reports_not_running_on_stderr_and_keeps_stdout_empty() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) =
        common::run_lpm(project.path(), lpm_home.path(), None, &["proxy", "status"]);

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stdout, "");
    let stderr = common::strip_ansi(&stderr);
    assert!(stderr.contains("Local proxy"), "stderr={stderr}");
    assert!(stderr.contains("not running"), "stderr={stderr}");
    assert!(stderr.contains("No proxy routes"), "stderr={stderr}");
}

#[test]
fn proxy_stop_json_reports_not_stopped_when_daemon_is_absent() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "stop"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["stopped"], false);
}

#[test]
fn proxy_start_detach_starts_background_control_daemon() {
    let _guard = proxy_daemon_test_guard();
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["proxy", "start", "--detach", "--http-port", "0"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stdout, "");
    let stderr = common::strip_ansi(&stderr);
    assert!(
        stderr.contains("local proxy control daemon started in the background"),
        "stderr={stderr}"
    );

    let status = wait_for_proxy_running_without_child(project.path(), lpm_home.path());
    assert!(
        status["httpAddr"].as_str().is_some(),
        "detached proxy should report a bound HTTP listener, got {status}"
    );

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "stop"],
    );
    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["stopped"], true);
}

#[test]
fn proxy_start_detach_json_reports_running_daemon_with_clean_stderr() {
    let _guard = proxy_daemon_test_guard();
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "start", "--detach", "--http-port", "0"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["running"], true);
    assert!(json["pid"].as_u64().is_some(), "stdout={stdout}");
    assert!(
        json["httpAddr"].as_str().is_some(),
        "detached proxy should report a bound HTTP listener, got {json}"
    );

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "stop"],
    );
    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    assert_eq!(common::parse_json_stdout(&stdout)["stopped"], true);
}

#[test]
fn proxy_install_and_uninstall_dry_run_report_service_plan_with_clean_fds() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        None,
        &[("LPM_PROXY_SERVICE_DRY_RUN", "1")],
        &[
            "--json",
            "proxy",
            "install",
            "--tls-port",
            "9443",
            "--http-redirect-port",
            "8080",
        ],
    );
    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["action"], "install");
    assert_eq!(json["changed"], false);
    assert_eq!(json["dryRun"], true);
    assert_eq!(
        json["args"],
        serde_json::json!([
            "proxy",
            "start",
            "--tls-port",
            "9443",
            "--http-redirect-port",
            "8080"
        ])
    );
    assert_eq!(json["privilegedForwarder"], serde_json::Value::Null);

    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        None,
        &[("LPM_PROXY_SERVICE_DRY_RUN", "1")],
        &["--json", "proxy", "uninstall"],
    );
    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["action"], "uninstall");
    assert_eq!(json["changed"], false);
    assert_eq!(json["dryRun"], true);
}

#[cfg(unix)]
#[test]
fn proxy_install_privileged_ports_dry_run_reports_forwarder_plan_with_clean_fds() {
    if running_as_root() {
        return;
    }
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        None,
        &[("LPM_PROXY_SERVICE_DRY_RUN", "1")],
        &["--json", "proxy", "install", "--privileged-ports"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["action"], "install");
    assert_eq!(json["dryRun"], true);
    assert_eq!(json["args"][0], "proxy");
    assert_eq!(json["args"][1], "start");
    assert!(
        json["args"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("--tls-port"))
    );
    assert!(
        json["args"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("--http-redirect-port"))
    );
    assert!(
        !json["args"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("443")),
        "user service must bind high backend ports: {json}"
    );
    assert!(
        !json["args"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("80")),
        "user service must bind high backend ports: {json}"
    );

    let forwarder = &json["privilegedForwarder"];
    assert_eq!(forwarder["service"], "dev.lpm.proxy.forwarder");
    assert_eq!(forwarder["args"][0], "proxy");
    assert_eq!(forwarder["args"][1], "forwarder");
    assert_eq!(forwarder["args"][2], "--forwarder-config");
    assert_eq!(forwarder["args"][3], forwarder["configPath"]);
    assert!(
        forwarder["statePath"]
            .as_str()
            .unwrap()
            .starts_with(lpm_home.path().to_str().unwrap()),
        "state path should stay in isolated LPM_HOME: {forwarder}"
    );
    let rules = forwarder["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    let https = rules
        .iter()
        .find(|rule| rule["name"] == "https")
        .expect("https forwarder rule");
    assert_eq!(https["listenAddr"], "127.0.0.1:443");
    assert!(socket_addr_port(&https["targetAddr"]) >= 1024);
    let redirect = rules
        .iter()
        .find(|rule| rule["name"] == "httpRedirect")
        .expect("redirect forwarder rule");
    assert_eq!(redirect["listenAddr"], "127.0.0.1:80");
    assert!(socket_addr_port(&redirect["targetAddr"]) >= 1024);
}

#[cfg(unix)]
#[test]
fn proxy_install_privileged_ports_uses_low_external_ports_when_config_uses_high_port() {
    if running_as_root() {
        return;
    }
    let (project, lpm_home) = isolated_dirs();
    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"proxy":{"host":"app.localhost","port":9443,"httpRedirect":true}}"#,
    )
    .expect("write lpm.json");

    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        None,
        &[("LPM_PROXY_SERVICE_DRY_RUN", "1")],
        &["--json", "proxy", "install", "--privileged-ports"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    let forwarder = &json["privilegedForwarder"];
    let rules = forwarder["rules"].as_array().unwrap();
    let https = rules
        .iter()
        .find(|rule| rule["name"] == "https")
        .expect("https forwarder rule");
    assert_eq!(https["listenAddr"], "127.0.0.1:443");
    assert!(socket_addr_port(&https["targetAddr"]) >= 1024);
}

#[cfg(unix)]
#[test]
fn proxy_uninstall_privileged_ports_dry_run_reports_forwarder_artifacts_with_clean_fds() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm_with_env(
        project.path(),
        lpm_home.path(),
        None,
        &[("LPM_PROXY_SERVICE_DRY_RUN", "1")],
        &["--json", "proxy", "uninstall", "--privileged-ports"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["action"], "uninstall");
    assert_eq!(json["dryRun"], true);
    let forwarder = &json["privilegedForwarder"];
    assert_eq!(forwarder["service"], "dev.lpm.proxy.forwarder");
    assert_eq!(forwarder["args"][1], "forwarder");
    assert_eq!(forwarder["args"][3], forwarder["configPath"]);
    assert_eq!(forwarder["rules"], serde_json::json!([]));
}

#[cfg(unix)]
#[test]
fn proxy_install_privileged_ports_rejects_plain_http_listener() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &[
            "proxy",
            "install",
            "--privileged-ports",
            "--http-port",
            "80",
        ],
    );

    assert!(
        !status.success(),
        "plain HTTP forwarding should be rejected"
    );
    assert_eq!(stdout, "");
    let stderr = common::strip_ansi(&stderr);
    assert!(stderr.contains("plain `--http-port`"), "stderr={stderr}");
}

#[test]
fn proxy_start_rejects_privileged_ports_flag() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["proxy", "start", "--privileged-ports"],
    );

    assert!(
        !status.success(),
        "start should reject privileged install flag"
    );
    assert_eq!(stdout, "");
    let stderr = common::strip_ansi(&stderr);
    assert!(stderr.contains("only valid with"), "stderr={stderr}");
}

#[test]
fn proxy_replace_flag_requires_privileged_install() {
    let (project, lpm_home) = isolated_dirs();

    for args in [
        &["proxy", "start", "--replace"][..],
        &["proxy", "install", "--replace"][..],
        &["proxy", "uninstall", "--privileged-ports", "--replace"][..],
    ] {
        let (status, stdout, stderr) = common::run_lpm(project.path(), lpm_home.path(), None, args);

        assert!(
            !status.success(),
            "`--replace` should reject invalid action combination {args:?}"
        );
        assert_eq!(stdout, "");
        let stderr = common::strip_ansi(&stderr);
        assert!(
            stderr.contains("`--replace` is only valid"),
            "stderr={stderr}"
        );
        assert!(stderr.contains("proxy install"), "stderr={stderr}");
        assert!(stderr.contains("--privileged-ports"), "stderr={stderr}");
    }
}

#[cfg(unix)]
#[test]
fn proxy_install_rejects_privileged_user_service_ports() {
    let (project, lpm_home) = isolated_dirs();

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["proxy", "install", "--tls-port", "443"],
    );

    assert!(!status.success(), "install should reject privileged port");
    assert_eq!(stdout, "");
    let stderr = common::strip_ansi(&stderr);
    assert!(stderr.contains("user-scoped service"), "stderr={stderr}");
    assert!(stderr.contains("privileged port"), "stderr={stderr}");
    assert!(stderr.contains("proxy install"), "stderr={stderr}");
    assert!(stderr.contains("--privileged-"), "stderr={stderr}");
    assert!(stderr.contains("ports"), "stderr={stderr}");
    assert!(stderr.contains("9443"), "stderr={stderr}");
    assert!(!stderr.contains("not wired yet"), "stderr={stderr}");
}

#[test]
fn proxy_uninstall_rejects_listener_flags() {
    let (project, lpm_home) = isolated_dirs();

    for args in [
        &["proxy", "uninstall", "--tls-port", "9443"][..],
        &["proxy", "uninstall", "--http-port", "8080"][..],
    ] {
        let (status, stdout, stderr) = common::run_lpm(project.path(), lpm_home.path(), None, args);

        assert!(!status.success(), "listener flags should be rejected");
        assert_eq!(stdout, "");
        let stderr = common::strip_ansi(&stderr);
        assert!(stderr.contains("only valid with"), "stderr={stderr}");
    }
}

#[cfg(unix)]
fn running_as_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(unix)]
fn socket_addr_port(value: &serde_json::Value) -> u64 {
    value
        .as_str()
        .and_then(|addr| addr.rsplit_once(':'))
        .and_then(|(_, port)| port.parse::<u64>().ok())
        .expect("socket address with numeric port")
}

#[cfg(unix)]
#[test]
fn proxy_start_status_stop_round_trips_foreground_control_daemon() {
    let _guard = proxy_daemon_test_guard();
    let (project, lpm_home) = isolated_dirs();
    let mut child = common::lpm_command(project.path(), lpm_home.path(), None, &["proxy", "start"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");

    wait_for_proxy_running(project.path(), lpm_home.path(), &mut child);

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "stop"],
    );

    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["success"], true);
    assert_eq!(json["stopped"], true);

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll proxy child") {
            assert!(status.success(), "proxy child exited with {status}");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("proxy child did not exit after stop");
}

#[cfg(unix)]
#[test]
fn proxy_start_http_port_routes_registered_host() {
    let _guard = proxy_daemon_test_guard();
    let (project, lpm_home) = isolated_dirs();
    let upstream_port = spawn_echo_upstream();
    let mut child = common::lpm_command(
        project.path(),
        lpm_home.path(),
        None,
        &["proxy", "start", "--http-port", "0"],
    )
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn lpm proxy start");

    let status = wait_for_proxy_running(project.path(), lpm_home.path(), &mut child);
    let http_addr = status["httpAddr"]
        .as_str()
        .expect("status should include bound HTTP address")
        .to_string();
    let registered = tokio::runtime::Runtime::new()
        .expect("create tokio runtime")
        .block_on(lpm_proxy::send_request_to_path(
            &lpm_home.path().join("proxy.sock"),
            lpm_proxy::ProxyRequest::Register {
                owner_pid: std::process::id(),
                routes: vec![lpm_proxy::Route {
                    host: "app.localhost".to_string(),
                    upstream_port,
                    project_dir: project.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
        ))
        .expect("register proxy route");
    assert!(
        matches!(registered, lpm_proxy::ProxyResponse::Registered { .. }),
        "unexpected register response: {registered:?}"
    );

    let response = reqwest::blocking::Client::new()
        .post(format!("{http_addr}/through?ok=1"))
        .header("host", "app.localhost")
        .body("hello")
        .send()
        .expect("send through proxy");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.text().expect("read proxy response"),
        "POST /through?ok=1 hello host=app.localhost proto=http"
    );

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "stop"],
    );
    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["stopped"], true);
    wait_for_proxy_child_exit(&mut child);
}

#[cfg(unix)]
#[test]
fn proxy_start_uses_lpm_json_proxy_listener_defaults_without_explicit_flags() {
    let _guard = proxy_daemon_test_guard();
    let (project, lpm_home) = isolated_dirs();
    std::fs::write(
        project.path().join("lpm.json"),
        r#"{"proxy":{"host":"app.localhost","port":0,"httpRedirect":false}}"#,
    )
    .expect("write lpm.json");
    let mut child = common::lpm_command(project.path(), lpm_home.path(), None, &["proxy", "start"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");

    let status = wait_for_proxy_running(project.path(), lpm_home.path(), &mut child);

    assert!(
        status["tlsAddr"].as_str().is_some(),
        "proxy.port from lpm.json should start an HTTPS listener, got {status}"
    );
    assert_eq!(status["httpRedirectAddr"], serde_json::Value::Null);
    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "stop"],
    );
    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["stopped"], true);
    wait_for_proxy_child_exit(&mut child);
}

#[cfg(unix)]
#[test]
fn proxy_start_tls_port_routes_registered_host_with_project_cert() {
    let _guard = proxy_daemon_test_guard();
    let (project, lpm_home) = isolated_dirs();
    write_project_cert(project.path(), &["app.localhost"]);
    let upstream_port = spawn_echo_upstream();
    let mut child = common::lpm_command(
        project.path(),
        lpm_home.path(),
        None,
        &["proxy", "start", "--tls-port", "0"],
    )
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn lpm proxy start");

    let status = wait_for_proxy_running(project.path(), lpm_home.path(), &mut child);
    let tls_addr = status["tlsAddr"]
        .as_str()
        .expect("status should include bound HTTPS address")
        .to_string();
    let tls_port = tls_addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("tls addr should end in a port");
    let registered = tokio::runtime::Runtime::new()
        .expect("create tokio runtime")
        .block_on(lpm_proxy::send_request_to_path(
            &lpm_home.path().join("proxy.sock"),
            lpm_proxy::ProxyRequest::Register {
                owner_pid: std::process::id(),
                routes: vec![lpm_proxy::Route {
                    host: "app.localhost".to_string(),
                    upstream_port,
                    project_dir: project.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
        ))
        .expect("register proxy route");
    assert!(
        matches!(registered, lpm_proxy::ProxyResponse::Registered { .. }),
        "unexpected register response: {registered:?}"
    );

    let response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(
            "app.localhost",
            std::net::SocketAddr::from(([127, 0, 0, 1], tls_port)),
        )
        .build()
        .expect("build HTTPS client")
        .post(format!("https://app.localhost:{tls_port}/secure?ok=1"))
        .body("hello")
        .send()
        .expect("send through TLS proxy");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.text().expect("read proxy response"),
        format!("POST /secure?ok=1 hello host=app.localhost:{tls_port} proto=https")
    );

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "stop"],
    );
    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["stopped"], true);
    wait_for_proxy_child_exit(&mut child);
}

#[cfg(unix)]
#[test]
fn proxy_start_http_redirect_port_redirects_registered_host_to_https_listener() {
    let _guard = proxy_daemon_test_guard();
    let (project, lpm_home) = isolated_dirs();
    let mut child = common::lpm_command(
        project.path(),
        lpm_home.path(),
        None,
        &[
            "proxy",
            "start",
            "--tls-port",
            "0",
            "--http-redirect-port",
            "0",
        ],
    )
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn lpm proxy start");

    let status = wait_for_proxy_running(project.path(), lpm_home.path(), &mut child);
    let redirect_addr = status["httpRedirectAddr"]
        .as_str()
        .expect("status should include bound HTTP redirect address")
        .to_string();
    let tls_addr = status["tlsAddr"]
        .as_str()
        .expect("status should include bound HTTPS address")
        .to_string();
    let tls_port = tls_addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("tls addr should end in a port");
    let registered = tokio::runtime::Runtime::new()
        .expect("create tokio runtime")
        .block_on(lpm_proxy::send_request_to_path(
            &lpm_home.path().join("proxy.sock"),
            lpm_proxy::ProxyRequest::Register {
                owner_pid: std::process::id(),
                routes: vec![lpm_proxy::Route {
                    host: "app.localhost".to_string(),
                    upstream_port: 3000,
                    project_dir: project.path().to_path_buf(),
                    service: Some("web".to_string()),
                }],
            },
        ))
        .expect("register proxy route");
    assert!(
        matches!(registered, lpm_proxy::ProxyResponse::Registered { .. }),
        "unexpected register response: {registered:?}"
    );

    let response = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build HTTP client")
        .get(format!("{redirect_addr}/login?next=/app"))
        .header("host", "app.localhost")
        .send()
        .expect("request redirect listener");

    assert_eq!(response.status(), reqwest::StatusCode::MOVED_PERMANENTLY);
    let expected_location = format!("https://app.localhost:{tls_port}/login?next=/app");
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some(expected_location.as_str())
    );

    let (status, stdout, stderr) = common::run_lpm(
        project.path(),
        lpm_home.path(),
        None,
        &["--json", "proxy", "stop"],
    );
    assert!(status.success(), "stderr={stderr}");
    assert_eq!(stderr, "");
    let json = common::parse_json_stdout(&stdout);
    assert_eq!(json["stopped"], true);
    wait_for_proxy_child_exit(&mut child);
}

#[cfg(unix)]
fn wait_for_proxy_running(
    project: &std::path::Path,
    lpm_home: &std::path::Path,
    child: &mut std::process::Child,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll proxy child") {
            panic!("proxy child exited before status became running: {status}");
        }

        let (status, stdout, _) =
            common::run_lpm(project, lpm_home, None, &["--json", "proxy", "status"]);
        if status.success() {
            let json = common::parse_json_stdout(&stdout);
            if json["running"] == true {
                return json;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("proxy daemon did not become ready");
}

fn wait_for_proxy_running_without_child(
    project: &std::path::Path,
    lpm_home: &std::path::Path,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let (status, stdout, _) =
            common::run_lpm(project, lpm_home, None, &["--json", "proxy", "status"]);
        if status.success() {
            let json = common::parse_json_stdout(&stdout);
            if json["running"] == true {
                return json;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("detached proxy daemon did not become ready");
}

#[cfg(unix)]
fn wait_for_proxy_child_exit(child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll proxy child") {
            assert!(status.success(), "proxy child exited with {status}");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("proxy child did not exit after stop");
}

#[cfg(unix)]
fn spawn_echo_upstream() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind echo upstream");
    let port = listener.local_addr().expect("echo upstream addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                return;
            };
            handle_echo_connection(&mut stream);
        }
    });
    port
}

#[cfg(unix)]
fn handle_echo_connection(stream: &mut std::net::TcpStream) {
    use std::io::{Read, Write};

    let mut buffer = [0u8; 8192];
    let Ok(read) = stream.read(&mut buffer) else {
        return;
    };
    let request = String::from_utf8_lossy(&buffer[..read]);
    let mut request_line = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next().unwrap_or("-");
    let path = request_line.next().unwrap_or("/");
    let forwarded_host = request
        .lines()
        .find_map(|line| line.strip_prefix("x-forwarded-host: "))
        .unwrap_or("-");
    let forwarded_proto = request
        .lines()
        .find_map(|line| line.strip_prefix("x-forwarded-proto: "))
        .unwrap_or("-");
    let (head, body) = request.split_once("\r\n\r\n").unwrap_or(("", ""));
    let body = if head
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        decode_chunked_body(body.as_bytes())
    } else {
        body.as_bytes().to_vec()
    };
    let body = String::from_utf8_lossy(&body);
    let response_body =
        format!("{method} {path} {body} host={forwarded_host} proto={forwarded_proto}");
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());
}

#[cfg(unix)]
fn write_project_cert(project_dir: &std::path::Path, hosts: &[&str]) {
    let (ca_cert_pem, ca_key_pem) =
        lpm_cert::ca::generate_ca_with_options(lpm_cert::ca::CaOptions::default())
            .expect("generate test CA");
    let extra_hostnames = hosts
        .iter()
        .map(|host| (*host).to_string())
        .collect::<Vec<_>>();
    let (cert_pem, key_pem) =
        lpm_cert::cert::generate_project_cert(&ca_cert_pem, &ca_key_pem, &extra_hostnames)
            .expect("generate project cert");
    let cert_dir = lpm_cert::paths::project_cert_dir(project_dir).expect("project cert dir");
    std::fs::create_dir_all(&cert_dir).expect("create project cert dir");
    std::fs::write(cert_dir.join("cert.pem"), cert_pem).expect("write cert");
    lpm_cert::write_key_file(&cert_dir.join("key.pem"), key_pem.as_bytes()).expect("write key");
}

#[cfg(unix)]
fn decode_chunked_body(mut bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    while let Some(line_end) = bytes.windows(2).position(|window| window == b"\r\n") {
        let size = std::str::from_utf8(&bytes[..line_end])
            .ok()
            .and_then(|line| usize::from_str_radix(line.trim(), 16).ok())
            .unwrap_or(0);
        bytes = &bytes[line_end + 2..];
        if size == 0 || bytes.len() < size {
            break;
        }
        decoded.extend_from_slice(&bytes[..size]);
        bytes = bytes.get(size + 2..).unwrap_or_default();
    }
    decoded
}
