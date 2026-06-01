mod support;

#[cfg(unix)]
use std::process::{Child, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};
#[cfg(unix)]
use support::{TempProject, lpm, lpm_spawnable};

#[cfg(unix)]
#[test]
fn dev_registers_proxy_routes_and_prepares_cert_without_enabling_app_https() {
    let project = TempProject::empty(r#"{"name":"local-domain-dev","version":"1.0.0"}"#);
    project.write_file(
        "server.js",
        r#"
const fs = require('fs');
const http = require('http');

fs.writeFileSync('env-observed.json', JSON.stringify({
  nodeExtraCaCerts: process.env.NODE_EXTRA_CA_CERTS || null,
  sslCertFile: process.env.SSL_CERT_FILE || null,
  sslKeyFile: process.env.SSL_KEY_FILE || null,
  port: process.env.PORT || null
}));

const server = http.createServer((_, response) => response.end('ok'));
server.listen(process.env.PORT, '127.0.0.1', () => {
  setTimeout(() => server.close(() => process.exit(0)), 8000);
});
"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "web": {
                    "command": "node server.js",
                    "host": "web.localhost"
                }
            }
        }"#,
    );

    let mut proxy = lpm_spawnable(&project)
        .args(["proxy", "start", "--tls-port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");
    wait_for_proxy_running(&project, &mut proxy);

    let mut dev_command = lpm_spawnable(&project);
    dev_command
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", trust_store_dir(&project))
        .env_remove("NODE_EXTRA_CA_CERTS")
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_KEY_FILE")
        .stdin(Stdio::null());
    let dev = dev_command.spawn().expect("spawn lpm dev");

    let (route, dev) = wait_for_proxy_route_or_dev_exit(&project, "web.localhost", dev);
    let upstream_port = route["upstreamPort"]
        .as_u64()
        .expect("route should expose an upstream port");
    assert!((3000..=u64::from(u16::MAX)).contains(&upstream_port));
    assert_port_override_persisted(&project, "web", upstream_port);
    assert_proxy_tls_routes_to_service(&project, "web.localhost");

    let output = dev.wait_with_output().expect("wait for lpm dev to finish");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("https://web.localhost -> auto port"),
        "startup banner should show the configured host before port assignment, got:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("web.localhost -> localhost:{upstream_port}")),
        "registered route output should show the final assigned port, got:\n{stderr}"
    );
    assert_app_https_env_was_not_injected(&project, upstream_port);
    assert_proxy_cert_covers_host(&project, "web.localhost");

    wait_for_proxy_route_absent(&project, "web.localhost");
    stop_proxy(&project, &mut proxy);
}

#[cfg(unix)]
#[test]
fn dev_auto_starts_detached_https_proxy_for_local_domain_hosts() {
    let project = TempProject::empty(r#"{"name":"local-domain-dev","version":"1.0.0"}"#);
    project.write_file(
        "server.js",
        r#"
const http = require('http');

const server = http.createServer((_, response) => response.end('ok'));
server.listen(process.env.PORT, '127.0.0.1', () => {
  setTimeout(() => server.close(() => process.exit(0)), 8000);
});
"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "proxy": {
                "port": 0,
                "httpRedirect": false
            },
            "services": {
                "web": {
                    "command": "node server.js",
                    "host": "web.localhost"
                }
            }
        }"#,
    );

    let mut dev_command = lpm_spawnable(&project);
    dev_command
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", trust_store_dir(&project))
        .stdin(Stdio::null());
    let dev = dev_command.spawn().expect("spawn lpm dev");

    let (route, dev) = wait_for_proxy_route_or_dev_exit(&project, "web.localhost", dev);
    assert!(
        proxy_status(&project)["tlsAddr"].as_str().is_some(),
        "auto-started proxy should expose a TLS listener"
    );
    assert_proxy_tls_routes_to_service(&project, "web.localhost");

    let output = dev.wait_with_output().expect("wait for lpm dev to finish");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("local proxy control daemon started in the background"),
        "dev should report the auto-started daemon, got:\n{stderr}"
    );
    assert!(
        route["upstreamPort"].as_u64().is_some(),
        "route should expose an upstream port: {route}"
    );

    wait_for_proxy_route_absent(&project, "web.localhost");
    stop_detached_proxy(&project);
}

#[cfg(unix)]
#[test]
fn dev_writes_and_removes_hosts_file_entries_for_non_localhost_host() {
    let project = TempProject::empty(r#"{"name":"local-domain-dev","version":"1.0.0"}"#);
    project.write_file(
        "server.js",
        r#"
const http = require('http');

const server = http.createServer((_, response) => response.end('ok'));
server.listen(process.env.PORT, '127.0.0.1', () => {
  setTimeout(() => server.close(() => process.exit(0)), 8000);
});
"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "web": {
                    "command": "node server.js",
                    "host": "web.test"
                }
            }
        }"#,
    );
    project.write_file("hosts", "127.0.0.1 localhost\n");
    let hosts_path = project.path().join("hosts");

    let mut proxy = lpm_spawnable(&project)
        .args(["proxy", "start", "--tls-port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");
    wait_for_proxy_running(&project, &mut proxy);

    let mut dev_command = lpm_spawnable(&project);
    dev_command
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", trust_store_dir(&project))
        .env("LPM_HOSTS_FILE", &hosts_path)
        .stdin(Stdio::null());
    let dev = dev_command.spawn().expect("spawn lpm dev");

    wait_for_proxy_route(&project, "web.test");
    assert_hosts_file_contains_managed_entry(&hosts_path, "web.test");
    assert_proxy_tls_routes_to_service(&project, "web.test");

    let output = dev.wait_with_output().expect("wait for lpm dev to finish");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_hosts_file_removed_managed_entry(&hosts_path, "web.test");
    assert_hosts_file_backup_exists(&project);
    assert_proxy_cert_covers_host(&project, "web.test");

    wait_for_proxy_route_absent(&project, "web.test");
    stop_proxy(&project, &mut proxy);
}

#[cfg(unix)]
#[test]
fn dev_aborts_non_interactive_non_localhost_host_without_hosts_file_consent() {
    let project = TempProject::empty(r#"{"name":"local-domain-dev","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "web": {
                    "command": "node server.js",
                    "host": "web.test"
                }
            }
        }"#,
    );
    project.write_file("hosts", "127.0.0.1 localhost\n");
    let hosts_path = project.path().join("hosts");
    trust_test_ca(&project);

    let mut proxy = lpm_spawnable(&project)
        .args(["proxy", "start", "--tls-port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");
    wait_for_proxy_running(&project, &mut proxy);

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open"])
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", trust_store_dir(&project))
        .env("LPM_HOSTS_FILE", &hosts_path)
        .output()
        .expect("run lpm dev");

    assert!(
        !output.status.success(),
        "dev should fail before hosts-file mutation without non-interactive consent"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("non-interactive shell: pass `--yes` to consent to updating")
            && stderr.contains("the hosts file for local domains (web.test)"),
        "stderr should explain hosts-file consent, got:\n{stderr}"
    );
    assert!(
        stderr.contains("web.test"),
        "stderr should name the host that needs consent, got:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&hosts_path).expect("read hosts file"),
        "127.0.0.1 localhost\n"
    );
    assert!(
        proxy_status(&project)["routes"]
            .as_array()
            .expect("routes should be an array")
            .is_empty()
    );

    stop_proxy(&project, &mut proxy);
}

#[cfg(unix)]
#[test]
fn concurrent_dev_projects_share_one_https_proxy_daemon() {
    let project_a = TempProject::empty(r#"{"name":"local-domain-a","version":"1.0.0"}"#);
    let project_b = TempProject::empty(r#"{"name":"local-domain-b","version":"1.0.0"}"#);
    write_localhost_service_project(&project_a, "alpha.localhost");
    write_localhost_service_project(&project_b, "beta.localhost");

    let mut proxy = lpm_spawnable(&project_a)
        .args(["proxy", "start", "--tls-port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");
    wait_for_proxy_running(&project_a, &mut proxy);

    let shared_lpm_home = project_a.home().join(".lpm");
    let shared_trust_store = trust_store_dir(&project_a);
    let mut dev_a_command = lpm_spawnable(&project_a);
    dev_a_command
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", &shared_trust_store)
        .stdin(Stdio::null());
    let dev_a = dev_a_command.spawn().expect("spawn first lpm dev");

    let mut dev_b_command = lpm_spawnable(&project_b);
    dev_b_command
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_HOME", &shared_lpm_home)
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", &shared_trust_store)
        .stdin(Stdio::null());
    let dev_b = dev_b_command.spawn().expect("spawn second lpm dev");

    wait_for_proxy_route(&project_a, "alpha.localhost");
    wait_for_proxy_route(&project_a, "beta.localhost");
    assert_proxy_tls_routes_to_service(&project_a, "alpha.localhost");
    assert_proxy_tls_routes_to_service(&project_a, "beta.localhost");

    let routes = proxy_status(&project_a)["routes"]
        .as_array()
        .expect("routes should be an array")
        .clone();
    assert_eq!(
        routes
            .iter()
            .filter(|route| route["host"] == "alpha.localhost" || route["host"] == "beta.localhost")
            .count(),
        2,
        "shared daemon should contain both project routes: {routes:?}"
    );

    let output_a = dev_a.wait_with_output().expect("wait for first lpm dev");
    let output_b = dev_b.wait_with_output().expect("wait for second lpm dev");
    assert!(
        output_a.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_a.stdout),
        String::from_utf8_lossy(&output_a.stderr)
    );
    assert!(
        output_b.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_b.stdout),
        String::from_utf8_lossy(&output_b.stderr)
    );

    wait_for_proxy_route_absent(&project_a, "alpha.localhost");
    wait_for_proxy_route_absent(&project_a, "beta.localhost");
    stop_proxy(&project_a, &mut proxy);
}

#[cfg(unix)]
#[test]
fn concurrent_dev_projects_reject_duplicate_proxy_host_on_shared_daemon() {
    let project_a = TempProject::empty(r#"{"name":"local-domain-a","version":"1.0.0"}"#);
    let project_b = TempProject::empty(r#"{"name":"local-domain-b","version":"1.0.0"}"#);
    write_localhost_service_project(&project_a, "shared.localhost");
    write_localhost_service_project(&project_b, "shared.localhost");

    let mut proxy = lpm_spawnable(&project_a)
        .args(["proxy", "start", "--tls-port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");
    wait_for_proxy_running(&project_a, &mut proxy);

    let shared_lpm_home = project_a.home().join(".lpm");
    let shared_trust_store = trust_store_dir(&project_a);
    let mut dev_a_command = lpm_spawnable(&project_a);
    dev_a_command
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", &shared_trust_store)
        .stdin(Stdio::null());
    let dev_a = dev_a_command.spawn().expect("spawn first lpm dev");

    let first_route = wait_for_proxy_route(&project_a, "shared.localhost");
    assert_proxy_tls_routes_to_service(&project_a, "shared.localhost");

    let output_b = lpm(&project_b)
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_HOME", &shared_lpm_home)
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", &shared_trust_store)
        .output()
        .expect("run second lpm dev");
    assert!(
        !output_b.status.success(),
        "second project should fail on duplicate proxy host; stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_b.stdout),
        String::from_utf8_lossy(&output_b.stderr)
    );
    let stderr_b = String::from_utf8_lossy(&output_b.stderr);
    assert!(
        stderr_b.contains("local proxy route registration failed")
            && stderr_b.contains("shared.localhost")
            && stderr_b.contains("already registered"),
        "duplicate-host failure should be explicit, got:\n{stderr_b}"
    );

    let routes = proxy_status(&project_a)["routes"]
        .as_array()
        .expect("routes should be an array")
        .clone();
    let shared_routes: Vec<&serde_json::Value> = routes
        .iter()
        .filter(|route| route["host"] == "shared.localhost")
        .collect();
    assert_eq!(
        shared_routes.len(),
        1,
        "duplicate project must not add a second shared.localhost route: {routes:?}"
    );
    assert_eq!(
        shared_routes[0]["leaseId"], first_route["leaseId"],
        "duplicate project must not replace the first lease"
    );

    let output_a = dev_a.wait_with_output().expect("wait for first lpm dev");
    assert!(
        output_a.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_a.stdout),
        String::from_utf8_lossy(&output_a.stderr)
    );

    wait_for_proxy_route_absent(&project_a, "shared.localhost");
    stop_proxy(&project_a, &mut proxy);
}

#[cfg(unix)]
#[test]
fn dev_removes_hosts_file_entry_when_proxy_route_registration_fails() {
    let project_a = TempProject::empty(r#"{"name":"local-domain-a","version":"1.0.0"}"#);
    let project_b = TempProject::empty(r#"{"name":"local-domain-b","version":"1.0.0"}"#);
    write_localhost_service_project(&project_a, "shared.test");
    write_localhost_service_project(&project_b, "shared.test");
    project_a.write_file("hosts", "127.0.0.1 localhost\n");
    project_b.write_file("hosts", "127.0.0.1 localhost\n");
    let hosts_a = project_a.path().join("hosts");
    let hosts_b = project_b.path().join("hosts");

    let mut proxy = lpm_spawnable(&project_a)
        .args(["proxy", "start", "--tls-port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");
    wait_for_proxy_running(&project_a, &mut proxy);

    let shared_lpm_home = project_a.home().join(".lpm");
    let shared_trust_store = trust_store_dir(&project_a);
    let mut dev_a_command = lpm_spawnable(&project_a);
    dev_a_command
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", &shared_trust_store)
        .env("LPM_HOSTS_FILE", &hosts_a)
        .stdin(Stdio::null());
    let dev_a = dev_a_command.spawn().expect("spawn first lpm dev");

    let first_route = wait_for_proxy_route(&project_a, "shared.test");
    assert_hosts_file_contains_managed_entry(&hosts_a, "shared.test");

    let output_b = lpm(&project_b)
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .env("LPM_HOME", &shared_lpm_home)
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", &shared_trust_store)
        .env("LPM_HOSTS_FILE", &hosts_b)
        .output()
        .expect("run second lpm dev");
    assert!(
        !output_b.status.success(),
        "second project should fail on duplicate proxy host; stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_b.stdout),
        String::from_utf8_lossy(&output_b.stderr)
    );
    let stderr_b = String::from_utf8_lossy(&output_b.stderr);
    assert!(
        stderr_b.contains("local proxy route registration failed")
            && stderr_b.contains("shared.test")
            && stderr_b.contains("already registered"),
        "duplicate-host failure should be explicit, got:\n{stderr_b}"
    );
    assert_hosts_file_removed_managed_entry(&hosts_b, "shared.test");

    let routes = proxy_status(&project_a)["routes"]
        .as_array()
        .expect("routes should be an array")
        .clone();
    let shared_routes: Vec<&serde_json::Value> = routes
        .iter()
        .filter(|route| route["host"] == "shared.test")
        .collect();
    assert_eq!(
        shared_routes.len(),
        1,
        "duplicate project must not add a second shared.test route: {routes:?}"
    );
    assert_eq!(
        shared_routes[0]["leaseId"], first_route["leaseId"],
        "duplicate project must not replace the first lease"
    );

    let output_a = dev_a.wait_with_output().expect("wait for first lpm dev");
    assert!(
        output_a.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output_a.stdout),
        String::from_utf8_lossy(&output_a.stderr)
    );
    assert_hosts_file_removed_managed_entry(&hosts_a, "shared.test");

    wait_for_proxy_route_absent(&project_a, "shared.test");
    stop_proxy(&project_a, &mut proxy);
}

#[cfg(unix)]
#[test]
fn dev_rejects_configured_host_when_proxy_has_no_https_listener() {
    let project = TempProject::empty(r#"{"name":"local-domain-dev","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "web": {
                    "command": "node server.js",
                    "host": "web.localhost"
                }
            }
        }"#,
    );

    let mut proxy = lpm_spawnable(&project)
        .args(["proxy", "start", "--http-port", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lpm proxy start");
    wait_for_proxy_running(&project, &mut proxy);

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--yes"])
        .output()
        .expect("run lpm dev");
    assert!(
        !output.status.success(),
        "dev should fail without a proxy HTTPS listener"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("without an HTTPS listener"),
        "stderr should explain the HTTPS listener requirement, got:\n{stderr}"
    );
    assert!(
        stderr.contains("lpm proxy start --tls-port 9443"),
        "stderr should include the restart hint, got:\n{stderr}"
    );
    assert!(
        proxy_status(&project)["routes"]
            .as_array()
            .expect("routes should be an array")
            .is_empty()
    );

    stop_proxy(&project, &mut proxy);
}

#[cfg(unix)]
fn write_localhost_service_project(project: &TempProject, host: &str) {
    project.write_file(
        "server.js",
        r#"
const http = require('http');

const server = http.createServer((_, response) => response.end('ok'));
server.listen(process.env.PORT, '127.0.0.1', () => {
  setTimeout(() => server.close(() => process.exit(0)), 8000);
});
"#,
    );
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
            "services": {{
                "web": {{
                    "command": "node server.js",
                    "host": "{host}"
                }}
            }}
        }}"#
        ),
    );
}

#[cfg(unix)]
fn wait_for_proxy_running(project: &TempProject, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll proxy child") {
            panic!("proxy child exited before becoming ready: {status}");
        }
        if proxy_status(project)["running"] == true {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    panic!("proxy daemon did not become ready");
}

#[cfg(unix)]
fn wait_for_proxy_route(project: &TempProject, host: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let status = proxy_status(project);
        if let Some(route) = status["routes"]
            .as_array()
            .expect("routes should be an array")
            .iter()
            .find(|route| route["host"] == host)
        {
            return route.clone();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("proxy route {host} did not appear");
}

#[cfg(unix)]
fn wait_for_proxy_route_or_dev_exit(
    project: &TempProject,
    host: &str,
    mut dev: Child,
) -> (serde_json::Value, Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let status = proxy_status(project);
        if let Some(route) = status["routes"]
            .as_array()
            .expect("routes should be an array")
            .iter()
            .find(|route| route["host"] == host)
        {
            return (route.clone(), dev);
        }
        if let Some(status) = dev.try_wait().expect("poll lpm dev child") {
            let output = dev.wait_with_output().expect("collect lpm dev output");
            panic!(
                "lpm dev exited before proxy route {host} appeared with {status}; stdout={}\nstderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = dev.kill();
    let output = dev.wait_with_output().expect("collect lpm dev output");
    panic!(
        "proxy route {host} did not appear; stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn wait_for_proxy_route_absent(project: &TempProject, host: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let status = proxy_status(project);
        let found = status["routes"]
            .as_array()
            .expect("routes should be an array")
            .iter()
            .any(|route| route["host"] == host);
        if !found {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("proxy route {host} did not disappear");
}

#[cfg(unix)]
fn assert_proxy_tls_routes_to_service(project: &TempProject, host: &str) {
    let tls_port = proxy_tls_port(project);
    let response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .resolve(host, std::net::SocketAddr::from(([127, 0, 0, 1], tls_port)))
        .build()
        .expect("build TLS client")
        .get(format!("https://{host}:{tls_port}/"))
        .send()
        .expect("request through TLS proxy");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().expect("read TLS proxy response"), "ok");
}

#[cfg(unix)]
fn proxy_tls_port(project: &TempProject) -> u16 {
    proxy_status(project)["tlsAddr"]
        .as_str()
        .and_then(|addr| addr.rsplit_once(':'))
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("proxy status should include a TLS listener port")
}

#[cfg(unix)]
fn assert_app_https_env_was_not_injected(project: &TempProject, upstream_port: u64) {
    let observed: serde_json::Value = serde_json::from_str(&project.read_file("env-observed.json"))
        .expect("parse env-observed.json");
    assert_eq!(
        observed["nodeExtraCaCerts"],
        serde_json::Value::Null,
        "proxy-only hosts must not inject framework HTTPS env"
    );
    assert_eq!(
        observed["sslCertFile"],
        serde_json::Value::Null,
        "proxy-only hosts must not inject framework HTTPS env"
    );
    assert_eq!(
        observed["sslKeyFile"],
        serde_json::Value::Null,
        "proxy-only hosts must not inject framework HTTPS env"
    );
    assert_eq!(observed["port"], upstream_port.to_string());
}

#[cfg(unix)]
fn assert_proxy_cert_covers_host(project: &TempProject, host: &str) {
    let status = cert_status(project);
    assert_eq!(status["ca"]["exists"], serde_json::json!(true));
    assert_eq!(status["ca"]["trusted"], serde_json::json!(true));
    assert_eq!(status["project"]["exists"], serde_json::json!(true));
    let hostnames = status["project"]["hostnames"]
        .as_array()
        .expect("cert status hostnames should be an array");
    let typed_host = format!("DNSName({host})");
    assert!(
        hostnames.iter().any(|hostname| hostname
            .as_str()
            .is_some_and(|value| value == host || value == typed_host)),
        "project cert hostnames did not include {host}: {hostnames:?}"
    );
    let cert_pem = std::fs::read_to_string(project.path().join(".lpm/certs/cert.pem"))
        .expect("read project cert");
    let cert_blocks = cert_pem.matches("-----BEGIN CERTIFICATE-----").count();
    assert_eq!(
        cert_blocks, 2,
        "custom local-domain cert should be a leaf + constrained intermediate chain"
    );
}

#[cfg(unix)]
fn assert_port_override_persisted(project: &TempProject, service: &str, port: u64) {
    let content = std::fs::read_to_string(project.home().join(".lpm").join("ports.toml"))
        .expect("read persisted ports.toml");
    let parsed: toml::Value = content.parse().expect("parse ports.toml");
    let persisted = parsed
        .as_table()
        .expect("ports.toml should be a table")
        .values()
        .filter_map(toml::Value::as_table)
        .any(|project_ports| {
            project_ports.get(service).and_then(toml::Value::as_integer) == Some(port as i64)
        });
    assert!(persisted, "ports.toml did not persist {service}={port}");
}

#[cfg(unix)]
fn assert_hosts_file_contains_managed_entry(path: &std::path::Path, host: &str) {
    let content = std::fs::read_to_string(path).expect("read hosts file");
    assert!(
        content.contains("# >>> lpm:project-"),
        "hosts file should contain managed LPM block:\n{content}"
    );
    assert!(
        content.contains(&format!("127.0.0.1 {host}")),
        "hosts file should contain {host} loopback entry:\n{content}"
    );
}

#[cfg(unix)]
fn assert_hosts_file_removed_managed_entry(path: &std::path::Path, host: &str) {
    let content = std::fs::read_to_string(path).expect("read hosts file");
    assert!(
        !content.contains("# >>> lpm:project-"),
        "hosts file should not retain managed LPM block:\n{content}"
    );
    assert!(
        !content.contains(host),
        "hosts file should not retain {host} entry:\n{content}"
    );
    assert_eq!(content, "127.0.0.1 localhost\n");
}

#[cfg(unix)]
fn assert_hosts_file_backup_exists(project: &TempProject) {
    let backup_path = project.home().join(".lpm").join("hosts.bak");
    let backup = std::fs::read_to_string(&backup_path)
        .unwrap_or_else(|err| panic!("read hosts backup {}: {err}", backup_path.display()));
    assert_eq!(backup, "127.0.0.1 localhost\n");
}

#[cfg(unix)]
fn proxy_status(project: &TempProject) -> serde_json::Value {
    let output = lpm(project)
        .args(["--json", "proxy", "status"])
        .output()
        .expect("run lpm proxy status");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("parse proxy status JSON: {err}"))
}

#[cfg(unix)]
fn cert_status(project: &TempProject) -> serde_json::Value {
    let output = lpm(project)
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", trust_store_dir(project))
        .args(["--json", "cert", "status"])
        .output()
        .expect("run lpm cert status");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|err| panic!("parse cert status JSON: {err}"))
}

#[cfg(unix)]
fn trust_test_ca(project: &TempProject) {
    let output = lpm(project)
        .args(["--json", "cert", "trust"])
        .env("LPM_CERT_TEST_TRUST_STORE_DIR", trust_store_dir(project))
        .output()
        .expect("run lpm cert trust");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn trust_store_dir(project: &TempProject) -> std::path::PathBuf {
    project.home().join(".lpm").join("test-trust")
}

#[cfg(unix)]
fn stop_proxy(project: &TempProject, child: &mut Child) {
    let output = lpm(project)
        .args(["--json", "proxy", "stop"])
        .output()
        .expect("run lpm proxy stop");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
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
fn stop_detached_proxy(project: &TempProject) {
    let output = lpm(project)
        .args(["--json", "proxy", "stop"])
        .output()
        .expect("stop detached proxy");
    assert!(
        output.status.success(),
        "proxy stop should succeed; stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
