mod support;

use std::net::{TcpListener, TcpStream};

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    // SAFETY: signal 0 does not modify the target process. The PID comes from
    // the child fixture and is used only while this test owns that fixture.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

use support::mock_registry::MockRegistry;
use support::{
    TempProject, configure_fake_node, lpm, lpm_spawnable, lpm_with_registry, write_repeated_file,
};

#[test]
fn dev_rejects_an_invalid_env_schema_default_before_starting_the_service() {
    let project = TempProject::empty(
        r#"{
            "name":"invalid-env-default",
            "version":"1.0.0",
            "scripts":{"dev":"node should-not-run.js"}
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"APPLICATION_PORT":{"default":"70000","format":"port"}}}}"#,
    );
    project.write_file(
        "should-not-run.js",
        "require('fs').writeFileSync('spawned.txt', 'yes');\n",
    );

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run dev with an invalid env schema default");

    assert!(!output.status.success(), "invalid default must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid format"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !project.file_exists("spawned.txt"),
        "service started before env schema validation"
    );
}

#[cfg(unix)]
fn install_fake_managed_node(project: &TempProject, version: &str) {
    use std::os::unix::fs::PermissionsExt;

    let binary = project
        .home()
        .join(".lpm/runtimes/node")
        .join(version)
        .join("bin/node");
    std::fs::create_dir_all(binary.parent().unwrap()).expect("create managed Node bin directory");
    std::fs::write(&binary, format!("#!/bin/sh\necho v{version}\n"))
        .expect("write managed Node binary");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
        .expect("mark managed Node executable");
}

#[cfg(unix)]
fn install_fake_managed_bun(project: &TempProject, version: &str) {
    use std::os::unix::fs::PermissionsExt;

    let binary = project
        .home()
        .join(".lpm/runtimes/bun")
        .join(version)
        .join("bin/bun");
    std::fs::create_dir_all(binary.parent().unwrap()).expect("create managed Bun bin directory");
    std::fs::write(&binary, format!("#!/bin/sh\necho bun-v{version}\n"))
        .expect("write managed Bun binary");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
        .expect("mark managed Bun executable");
}

struct FrameworkBinCase {
    label: &'static str,
    package_name: &'static str,
    bin_name: &'static str,
    script: &'static str,
}

const FRAMEWORK_BIN_CASES: &[FrameworkBinCase] = &[
    FrameworkBinCase {
        label: "next",
        package_name: "next",
        bin_name: "next",
        script: "next dev",
    },
    FrameworkBinCase {
        label: "vite",
        package_name: "vite",
        bin_name: "vite",
        script: "vite --host 127.0.0.1",
    },
    FrameworkBinCase {
        label: "astro",
        package_name: "astro",
        bin_name: "astro",
        script: "astro dev",
    },
    FrameworkBinCase {
        label: "webpack",
        package_name: "webpack-cli",
        bin_name: "webpack",
        script: "webpack serve",
    },
    FrameworkBinCase {
        label: "remix",
        package_name: "@remix-run/dev",
        bin_name: "remix",
        script: "remix dev",
    },
    FrameworkBinCase {
        label: "react-router",
        package_name: "@react-router/dev",
        bin_name: "react-router",
        script: "react-router dev",
    },
    FrameworkBinCase {
        label: "nuxt",
        package_name: "@nuxt/cli",
        bin_name: "nuxt",
        script: "nuxt dev",
    },
    FrameworkBinCase {
        label: "sveltekit",
        package_name: "@sveltejs/kit",
        bin_name: "svelte-kit",
        script: "svelte-kit dev",
    },
    FrameworkBinCase {
        label: "storybook",
        package_name: "storybook",
        bin_name: "storybook",
        script: "storybook dev",
    },
];

#[test]
fn dev_rejects_oversized_nvmrc_before_probing_system_node() {
    let project = TempProject::empty(
        r#"{
        "name": "oversized-nvmrc-dev",
        "version": "1.0.0",
        "scripts": {"dev": "node server.js"}
    }"#,
    );
    project.write_file(".node-version", "20.18.0\n");
    let nvmrc_path = project.path().join(".nvmrc");
    write_repeated_file(
        &nvmrc_path,
        b"22\n#",
        b'a',
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES + 1,
        b"\n",
    );
    let marker_path = project.path().join("fake-node-invoked");
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.18.0");

    let output = command
        .env("LPM_FAKE_NODE_MARKER", &marker_path)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run dev with oversized .nvmrc");

    assert!(!output.status.success(), "oversized .nvmrc must fail");
    assert!(
        !marker_path.exists(),
        "system Node must not be probed after .nvmrc validation fails"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&nvmrc_path.display().to_string())
            && stderr.contains("16777216-byte limit"),
        "error must identify .nvmrc and limit; got:\n{stderr}"
    );
}

#[test]
fn dev_passes_selected_port_to_single_service_script() {
    let project = TempProject::empty(
        r#"{"name":"dev-port","version":"1.0.0","scripts":{"dev":"node check-port.js"}}"#,
    );
    project.write_file(
        "check-port.js",
        r#"
if (process.env.PORT !== '4567') {
  console.error(`expected PORT=4567, got ${process.env.PORT || '<unset>'}`);
  process.exit(42);
}
"#,
    );

    let output = lpm(&project)
        .args([
            "dev",
            "--no-install",
            "--no-open",
            "--no-dashboard",
            "--port",
            "4567",
        ])
        .output()
        .expect("failed to run lpm dev");

    assert!(
        output.status.success(),
        "lpm dev should pass the selected port into single-service scripts\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn dev_reports_the_endpoint_selected_by_the_child_server() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve child server port");
    let actual_port = listener.local_addr().expect("read reserved port").port();
    drop(listener);

    let project = TempProject::empty(
        r#"{"name":"dev-detected-port","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const http = require('http');
const port = Number(process.env.LPM_TEST_ACTUAL_PORT);
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  console.log(`  ➜  Local: http://localhost:${port}/`);
  setTimeout(() => server.close(), 750);
});
"#,
    );

    let output = lpm(&project)
        .env("LPM_TEST_ACTUAL_PORT", actual_port.to_string())
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run lpm dev with a child-selected port");

    assert!(
        output.status.success(),
        "lpm dev should preserve the child exit status\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("  Local http://localhost:{actual_port}")),
        "LPM must report the endpoint owned by the child server\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        !stderr.contains("  Local http://localhost:3000"),
        "LPM must not report its fallback guess as the running server\nstderr:\n{stderr}",
    );
}

#[test]
fn dev_reports_an_explicit_port_only_after_the_child_owns_it() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve explicit dev port");
    let port = listener
        .local_addr()
        .expect("read explicit dev port")
        .port();
    drop(listener);
    let project = TempProject::empty(
        r#"{"name":"dev-explicit-port","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const http = require('http');
const port = Number(process.env.PORT);
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  console.log(`Local: http://localhost:${port}/`);
  setTimeout(() => server.close(), 750);
});
"#,
    );

    let output = lpm(&project)
        .args([
            "dev",
            "--no-install",
            "--no-open",
            "--no-dashboard",
            "--port",
            &port.to_string(),
        ])
        .output()
        .expect("run lpm dev with an explicit port");

    assert!(
        output.status.success(),
        "explicit-port fixture should exit cleanly\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("  Local http://localhost:{port}/")),
        "LPM must publish the owned explicit endpoint\nstderr:\n{stderr}"
    );
}

#[test]
fn dev_rejects_a_child_endpoint_that_ignores_the_explicit_port() {
    let requested_listener = TcpListener::bind("127.0.0.1:0").expect("reserve requested port");
    let requested_port = requested_listener
        .local_addr()
        .expect("read requested port")
        .port();
    let actual_listener = TcpListener::bind("127.0.0.1:0").expect("reserve actual port");
    let actual_port = actual_listener
        .local_addr()
        .expect("read actual port")
        .port();
    drop(requested_listener);
    drop(actual_listener);
    let project = TempProject::empty(
        r#"{"name":"dev-ignored-port","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const http = require('http');
const port = Number(process.env.LPM_TEST_ACTUAL_PORT);
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  console.log(`Local: http://localhost:${port}/`);
});
"#,
    );

    let output = lpm(&project)
        .env("LPM_TEST_ACTUAL_PORT", actual_port.to_string())
        .args([
            "dev",
            "--no-install",
            "--no-open",
            "--no-dashboard",
            "--port",
            &requested_port.to_string(),
        ])
        .output()
        .expect("run lpm dev with an ignored explicit port");

    assert!(!output.status.success(), "ignored explicit port must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("ignored `--port {requested_port}`"))
            && stderr.contains(&format!("port {actual_port}")),
        "error must identify requested and actual ports\nstderr:\n{stderr}"
    );
}

#[cfg(debug_assertions)]
#[test]
fn dev_stops_the_child_when_https_frontend_setup_fails() {
    let occupied = TcpListener::bind("127.0.0.1:0").expect("occupy HTTPS frontend port");
    let frontend_port = occupied
        .local_addr()
        .expect("read occupied HTTPS frontend port")
        .port();
    let project = TempProject::empty(
        r#"{"name":"dev-frontend-failure","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const http = require('http');
const port = Number(process.env.PORT);
require('fs').writeFileSync('child-port.txt', String(port));
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  console.log(`Local: http://localhost:${port}/`);
  setTimeout(() => server.close(), 8000);
});
"#,
    );

    let output = lpm(&project)
        .env(
            "LPM_CERT_TEST_TRUST_STORE_DIR",
            project.home().join(".lpm").join("test-trust-store"),
        )
        .env(
            "LPM_CERT_AUDIT_DIR",
            project.home().join(".lpm").join("audit"),
        )
        .args([
            "dev",
            "--no-install",
            "--no-open",
            "--no-dashboard",
            "--https",
            "--yes",
            "--port",
            &frontend_port.to_string(),
        ])
        .output()
        .expect("run lpm dev with an occupied HTTPS frontend port");

    assert!(!output.status.success(), "occupied HTTPS port must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bind LPM HTTPS frontend") && stderr.contains(&frontend_port.to_string()),
        "fixture must reach the post-discovery frontend failure\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout),
    );
    let child_port: u16 = project.read_file("child-port.txt").parse().unwrap();
    let child_released = (0..20).any(|_| {
        if TcpStream::connect(("127.0.0.1", child_port)).is_err() {
            true
        } else {
            std::thread::sleep(std::time::Duration::from_millis(50));
            false
        }
    });
    assert!(
        child_released,
        "frontend setup failure must stop the child listener on port {child_port}\nstderr:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn dev_sigterm_stops_single_service_child_and_listener() {
    use std::io::Read;

    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve child server port");
    let port = listener
        .local_addr()
        .expect("read child server port")
        .port();
    drop(listener);

    let project = TempProject::empty(
        r#"{"name":"dev-sigterm","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const fs = require('fs');
const http = require('http');
const port = Number(process.env.PORT);
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  fs.writeFileSync('child.pid', String(process.pid));
  console.log(`Local: http://localhost:${port}/`);
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
"#,
    );

    let mut command = lpm_spawnable(&project);
    command.args([
        "dev",
        "--no-install",
        "--no-open",
        "--no-dashboard",
        "--port",
        &port.to_string(),
    ]);
    let mut lpm_child = command.spawn().expect("start single-service lpm dev");
    let readiness_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let child_pid = loop {
        if let Ok(pid) = std::fs::read_to_string(project.path().join("child.pid"))
            && TcpStream::connect(("127.0.0.1", port)).is_ok()
        {
            break pid.trim().parse::<u32>().expect("parse child PID");
        }
        if let Some(status) = lpm_child.try_wait().expect("inspect lpm dev") {
            panic!("lpm dev exited with {status} before its child became ready");
        }
        assert!(
            std::time::Instant::now() < readiness_deadline,
            "single-service child did not become ready"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    };

    // SAFETY: the PID belongs to the live LPM child spawned by this test.
    let signal_result = unsafe { libc::kill(lpm_child.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(signal_result, 0, "send SIGTERM to lpm dev");

    let exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let lpm_status = loop {
        if let Some(status) = lpm_child.try_wait().expect("wait for lpm dev shutdown") {
            break status;
        }
        if std::time::Instant::now() >= exit_deadline {
            let _ = lpm_child.kill();
            let _ = lpm_child.wait();
            panic!("lpm dev did not exit after SIGTERM");
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    lpm_child
        .stdout
        .take()
        .expect("capture lpm stdout")
        .read_to_string(&mut stdout)
        .expect("read lpm stdout");
    lpm_child
        .stderr
        .take()
        .expect("capture lpm stderr")
        .read_to_string(&mut stderr)
        .expect("read lpm stderr");

    let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < cleanup_deadline
        && (process_is_alive(child_pid) || TcpStream::connect(("127.0.0.1", port)).is_ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let child_survived = process_is_alive(child_pid);
    let listener_survived = TcpStream::connect(("127.0.0.1", port)).is_ok();
    if child_survived {
        // SAFETY: this PID was recorded by the fixture owned by this test.
        unsafe {
            libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
        }
    }

    assert!(
        lpm_status.success(),
        "lpm dev should shut down cleanly after SIGTERM (status {lpm_status})\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !child_survived && !listener_survived,
        "SIGTERM to lpm dev must stop child PID {child_pid} and listener {port}; child survived: {child_survived}, listener survived: {listener_survived}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn concurrent_vite_like_projects_report_their_own_child_endpoints() {
    let first_listener = TcpListener::bind("127.0.0.1:0").expect("reserve first Vite port");
    let first_port = first_listener.local_addr().expect("read first port").port();
    let second_listener = TcpListener::bind("127.0.0.1:0").expect("reserve second Vite port");
    let second_port = second_listener
        .local_addr()
        .expect("read second port")
        .port();
    drop(first_listener);
    drop(second_listener);

    let package_json = r#"{
        "name":"concurrent-vite",
        "version":"1.0.0",
        "scripts":{"dev":"node server.js"},
        "devDependencies":{"vite":"^7.0.0"}
    }"#;
    let first = TempProject::empty(package_json);
    let second = TempProject::empty(package_json);
    let server = r#"
const http = require('http');
const port = Number(process.env.LPM_TEST_ACTUAL_PORT);
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  console.log(`  ➜  Local: http://localhost:${port}/`);
  setTimeout(() => server.close(), 1000);
});
"#;
    first.write_file("server.js", server);
    second.write_file("server.js", server);

    let mut first_command = lpm_spawnable(&first);
    first_command
        .env("LPM_TEST_ACTUAL_PORT", first_port.to_string())
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"]);
    let mut second_command = lpm_spawnable(&second);
    second_command
        .env("LPM_TEST_ACTUAL_PORT", second_port.to_string())
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"]);

    let first_child = first_command.spawn().expect("start first lpm dev");
    let second_child = second_command.spawn().expect("start second lpm dev");
    let first_output = first_child
        .wait_with_output()
        .expect("wait for first lpm dev");
    let second_output = second_child
        .wait_with_output()
        .expect("wait for second lpm dev");

    assert!(first_output.status.success(), "first dev session failed");
    assert!(second_output.status.success(), "second dev session failed");
    let first_stderr = String::from_utf8_lossy(&first_output.stderr);
    let second_stderr = String::from_utf8_lossy(&second_output.stderr);
    assert!(first_stderr.contains(&format!("  Local http://localhost:{first_port}/")));
    assert!(!first_stderr.contains(&format!("  Local http://localhost:{second_port}/")));
    assert!(second_stderr.contains(&format!("  Local http://localhost:{second_port}/")));
    assert!(!second_stderr.contains(&format!("  Local http://localhost:{first_port}/")));
}

#[test]
fn multi_service_dev_loads_the_explicit_environment_mode() {
    let project = TempProject::empty(
        r#"{
            "name":"multi-service-env-mode",
            "version":"1.0.0"
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "worker": {
                    "command": "node record-env.js"
                }
            }
        }"#,
    );
    project.write_file(".env", "SELECTED_MODE=default\n");
    project.write_file(".env.staging", "SELECTED_MODE=staging\n");
    project.write_file(
        "record-env.js",
        r#"const fs = require('fs');
const http = require('http');
fs.writeFileSync('selected-mode.txt', process.env.SELECTED_MODE || '<unset>');
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(Number(process.env.PORT), '127.0.0.1', () => setTimeout(() => server.close(), 2000));"#,
    );

    let output = lpm(&project)
        .args([
            "dev",
            "--env",
            "staging",
            "--no-install",
            "--no-open",
            "--no-dashboard",
        ])
        .output()
        .expect("run multi-service dev with an explicit env mode");

    assert!(
        output.status.success(),
        "multi-service dev failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(project.read_file("selected-mode.txt"), "staging");
}

#[test]
fn multi_service_dev_scrubs_inherited_credentials() {
    let project = TempProject::empty(
        r#"{
            "name":"multi-service-env-scrub",
            "version":"1.0.0"
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "worker": {
                    "command": "node record-env.js"
                }
            }
        }"#,
    );
    project.write_file(
        "record-env.js",
        r#"const fs = require('fs');
const http = require('http');
fs.writeFileSync('child-env.json', JSON.stringify({
  token: process.env.LPM_TOKEN || null,
  ordinary: process.env.LPM_ORDINARY_VALUE || null
}));
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(Number(process.env.PORT), '127.0.0.1', () => setTimeout(() => server.close(), 2000));"#,
    );

    let output = lpm(&project)
        .env("LPM_TOKEN", "must-not-leak")
        .env("LPM_ORDINARY_VALUE", "preserved")
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run multi-service dev with inherited credentials");

    assert!(
        output.status.success(),
        "multi-service dev failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let child_env: serde_json::Value =
        serde_json::from_str(&project.read_file("child-env.json")).expect("parse child env");
    assert_eq!(child_env["token"], serde_json::Value::Null);
    assert_eq!(child_env["ordinary"], "preserved");
}

#[cfg(unix)]
#[test]
fn multi_service_dev_composes_root_and_service_local_runtimes() {
    let project = TempProject::empty(
        r#"{
            "name":"multi-service-local-runtimes",
            "version":"1.0.0",
            "private":true,
            "workspaces":["services/*"]
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
        "runtime":{"node":"22.0.0"},
        "services":{
            "api":{"command":"node --version && bun --version && service-tool","cwd":"services/api"},
            "worker":{"command":"true"}
        }
    }"#,
    );
    project.write_file(
        "services/api/package.json",
        r#"{"name":"multi-service-api","version":"1.0.0","engines":{"node":">=22"}}"#,
    );
    project.write_file("services/api/lpm.json", r#"{"runtime":{"bun":"1.3.14"}}"#);
    install_fake_managed_node(&project, "22.0.0");
    install_fake_managed_bun(&project, "1.3.14");
    project.write_file(
        "services/api/node_modules/.bin/service-tool",
        "#!/bin/sh\necho service-local-bin\n",
    );
    {
        use std::os::unix::fs::PermissionsExt;
        let tool = project
            .path()
            .join("services/api/node_modules/.bin/service-tool");
        std::fs::set_permissions(tool, std::fs::Permissions::from_mode(0o755))
            .expect("mark service-local tool executable");
    }

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run multi-service dev with service-local runtime selectors");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.status.success(),
        "multi-service dev failed:\n{combined}"
    );
    assert!(
        combined.contains("v22.0.0")
            && combined.contains("bun-v1.3.14")
            && combined.contains("service-local-bin"),
        "service did not receive root runtime, local runtime, and local bin:\n{combined}"
    );
}

#[cfg(unix)]
#[test]
fn multi_service_dev_rejects_service_node_that_violates_its_engine() {
    let project = TempProject::empty(
        r#"{
            "name":"multi-service-engine-gate",
            "version":"1.0.0",
            "private":true,
            "workspaces":["services/*"]
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
        "services":{
            "api":{"command":"touch service-started","cwd":"services/api"},
            "worker":{"command":"true"}
        }
    }"#,
    );
    project.write_file(
        "services/api/package.json",
        r#"{"name":"engine-gated-api","version":"1.0.0","engines":{"node":">=22"}}"#,
    );
    project.write_file("services/api/lpm.json", r#"{"runtime":{"node":"20.0.0"}}"#);
    install_fake_managed_node(&project, "20.0.0");

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run multi-service dev with an incompatible service runtime");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "engine mismatch did not fail:\n{combined}"
    );
    assert!(
        combined.contains(">=22") && combined.contains("20.0.0"),
        "engine mismatch did not identify the requirement and runtime:\n{combined}"
    );
    assert!(
        !project.file_exists("services/api/service-started"),
        "service spawned before its engine requirement was validated"
    );
}

#[cfg(unix)]
#[test]
fn single_service_dev_banner_reports_the_selected_managed_node() {
    let project = TempProject::empty(
        r#"{
            "name":"single-service-runtime-banner",
            "version":"1.0.0",
            "scripts":{"dev":"node server.js"}
        }"#,
    );
    project.write_file("lpm.json", r#"{"runtime":{"node":"22.0.0"}}"#);
    install_fake_managed_node(&project, "22.0.0");
    let system_node = std::process::Command::new("sh")
        .args(["-c", "command -v node"])
        .output()
        .expect("locate system Node");
    assert!(system_node.status.success(), "system Node is required");
    let system_node = String::from_utf8(system_node.stdout)
        .expect("system Node path is UTF-8")
        .trim()
        .to_string();
    let managed_node = project.home().join(".lpm/runtimes/node/22.0.0/bin/node");
    std::fs::write(
        &managed_node,
        format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = --version ]; then echo v22.0.0; else exec '{system_node}' \"$@\"; fi\n"
        ),
    )
    .expect("write managed Node proxy");
    project.write_file(
        "server.js",
        r#"const http = require('http');
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  console.log(`Local: http://localhost:${port}/`);
  setTimeout(() => server.close(), 750);
});"#,
    );
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.0.0");

    let output = command
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run single-service dev with a managed Node selector");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.status.success(),
        "single-service dev failed:\n{combined}"
    );
    let node_line = combined
        .lines()
        .find(|line| line.contains("● Node"))
        .unwrap_or_else(|| panic!("startup banner omitted Node:\n{combined}"));
    assert!(
        node_line.contains("v22.0.0") && node_line.contains("lpm.json"),
        "startup banner did not report the selected managed Node:\n{node_line}"
    );
}

#[test]
fn multi_service_reports_its_conflict_reassigned_port() {
    let occupied = (41_000..45_000)
        .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
        .expect("occupy configured service port");
    let occupied_port = occupied.local_addr().expect("read occupied port").port();
    let project = TempProject::empty(
        r#"{
            "name":"multi-service-port",
            "version":"1.0.0"
        }"#,
    );
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
                "services": {{
                    "web": {{
                        "command": "node server.js",
                        "port": {occupied_port},
                        "primary": true,
                        "readyTimeout": 3
                    }}
                }}
            }}"#
        ),
    );
    project.write_file(
        "server.js",
        r#"
const http = require('http');
const port = Number(process.env.PORT);
if (!Number.isInteger(port) || port === 0) {
  console.error(`invalid managed PORT: ${process.env.PORT}`);
  process.exit(42);
}
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  console.log(`Local: http://localhost:${port}/`);
  setTimeout(() => server.close(), 750);
});
"#,
    );

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run multi-service dev");

    assert!(
        output.status.success(),
        "multi-service fixture should exit cleanly\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let marker = "  Local http://localhost:";
    let local_port = stderr
        .find(marker)
        .and_then(|start| {
            stderr[start + marker.len()..]
                .split(|character: char| !character.is_ascii_digit())
                .next()
        })
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("resolved Local endpoint missing from stderr:\n{stderr}"));
    assert_ne!(
        local_port, occupied_port,
        "an unrelated listener must not satisfy primary-service readiness"
    );
    assert!(
        stderr.contains(&format!("-> :{local_port}")),
        "service banner and Local endpoint must use the same final port\nstderr:\n{stderr}"
    );
}

#[test]
fn dev_readiness_timeout_stops_before_starting_dependents() {
    let readiness_listener =
        TcpListener::bind("127.0.0.1:0").expect("reserve non-responsive readiness port");
    let readiness_port = readiness_listener
        .local_addr()
        .expect("read non-responsive readiness port")
        .port();
    let project = TempProject::empty(
        r#"{
            "name": "dev-readiness-timeout",
            "version": "1.0.0"
        }"#,
    );
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
            "services": {{
                "db": {{
                    "command": "node slow-service.js",
                    "readyUrl": "http://127.0.0.1:{readiness_port}/health",
                    "readyTimeout": 1
                }},
                "api": {{
                    "command": "node dependent.js",
                    "dependsOn": ["db"]
                }}
            }}
        }}"#
        ),
    );
    project.write_file("slow-service.js", "setTimeout(() => {}, 2500);\n");
    project.write_file(
        "dependent.js",
        "require('fs').writeFileSync('dependent-started', 'started');\n",
    );

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run lpm dev with a readiness timeout");

    assert!(
        !output.status.success(),
        "readiness timeout must fail startup\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !project.file_exists("dependent-started"),
        "a dependent must not start after its dependency fails readiness"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("service 'db' failed readiness")
            && stderr.contains(&format!(
                "timed out waiting for http://127.0.0.1:{readiness_port}/health (1s)"
            )),
        "error must identify the service and readiness target\nstderr:\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn multi_service_readiness_failure_stops_descendant_processes() {
    let descendant_listener = TcpListener::bind("127.0.0.1:0").expect("reserve descendant port");
    let descendant_port = descendant_listener
        .local_addr()
        .expect("read descendant port")
        .port();
    drop(descendant_listener);
    let readiness_listener =
        TcpListener::bind("127.0.0.1:0").expect("reserve non-responsive readiness port");
    let readiness_port = readiness_listener
        .local_addr()
        .expect("read non-responsive readiness port")
        .port();
    let project = TempProject::empty(r#"{"name":"descendant-cleanup","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
                "services":{{
                    "api":{{
                        "command":"node descendant.js {descendant_port} & sleep 30",
                        "readyUrl":"http://127.0.0.1:{readiness_port}/health",
                        "readyTimeout":1
                    }},
                    "worker":{{"command":"sleep 30"}}
                }}
            }}"#
        ),
    );
    project.write_file(
        "descendant.js",
        r#"const fs = require('fs');
const net = require('net');
const server = net.createServer(() => {});
server.listen(Number(process.argv[2]), '127.0.0.1', () => {
  fs.writeFileSync('descendant-ready', String(process.pid));
});"#,
    );

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run multi-service dev with a descendant process");
    assert!(!output.status.success(), "readiness failure must fail dev");

    let survived = TcpStream::connect(("127.0.0.1", descendant_port)).is_ok();
    if survived && let Ok(pid) = project.read_file("descendant-ready").trim().parse::<u32>() {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    assert!(
        !survived,
        "readiness failure left a descendant listening on port {descendant_port}"
    );
}

#[test]
fn dev_restarts_dependents_after_restarting_dependency_is_ready() {
    let db_listener = TcpListener::bind("127.0.0.1:0").expect("reserve database port");
    let db_port = db_listener.local_addr().expect("read database port").port();
    drop(db_listener);
    let api_listener = TcpListener::bind("127.0.0.1:0").expect("reserve API port");
    let api_port = api_listener.local_addr().expect("read API port").port();
    drop(api_listener);

    let project = TempProject::empty(
        r#"{
            "name": "dev-dependency-restart",
            "version": "1.0.0"
        }"#,
    );
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{
                "services": {{
                    "db": {{
                        "command": "node restarting-db.js {db_port}",
                        "readyUrl": "http://127.0.0.1:{db_port}/health",
                        "readyTimeout": 15,
                        "restart": true
                    }},
                    "api": {{
                        "command": "node dependent-api.js {api_port} {db_port}",
                        "readyUrl": "http://127.0.0.1:{api_port}/health",
                        "readyTimeout": 15,
                        "dependsOn": ["db"]
                    }}
                }}
            }}"#
        ),
    );
    project.write_file(
        "restarting-db.js",
        r#"
const fs = require('fs');
const http = require('http');
const port = Number(process.argv[2]);
const countPath = 'db-start-count';
const count = fs.existsSync(countPath)
  ? Number(fs.readFileSync(countPath, 'utf8')) + 1
  : 1;
fs.writeFileSync(countPath, String(count));
const server = http.createServer((request, response) => {
  if (count === 1 && request.url === '/restart') {
    response.end('restarting', () => server.close(() => process.exit(1)));
    return;
  }
  response.end('ok');
});
server.listen(port, '127.0.0.1', () => {
  if (count > 1) {
    setTimeout(() => server.close(() => process.exit(0)), 2500);
  }
});
"#,
    );
    project.write_file(
        "dependent-api.js",
        r#"
const fs = require('fs');
const http = require('http');
const port = Number(process.argv[2]);
const dbPort = Number(process.argv[3]);
const countPath = 'api-start-count';
const count = fs.existsSync(countPath)
  ? Number(fs.readFileSync(countPath, 'utf8')) + 1
  : 1;
fs.writeFileSync(countPath, String(count));
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  if (count === 1) {
    const request = http.get(`http://127.0.0.1:${dbPort}/restart`, response => response.resume());
    request.on('error', error => {
      console.error(error);
      process.exit(1);
    });
  } else {
    setTimeout(() => server.close(() => process.exit(0)), 1000);
  }
});
"#,
    );

    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .expect("run lpm dev with a restarting dependency");

    assert!(
        output.status.success(),
        "recovered service graph must exit successfully\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        project.read_file("api-start-count"),
        "2",
        "the dependent must restart after its dependency recovers\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn dev_auto_compat_materializes_project_local_entrypoint_for_framework_bins() {
    for case in FRAMEWORK_BIN_CASES {
        let project = project_for_framework_case(case);
        let mock = MockRegistry::start().await;
        mount_framework_case(&mock, case).await;

        let output = lpm_with_registry(&project, &mock.url())
            .env("LPM_STORE_VERSION", "v2")
            .args(["dev", "--no-open", "--no-dashboard", "--port", "4567"])
            .output()
            .unwrap_or_else(|e| panic!("failed to run lpm dev for {}: {e}", case.label));

        assert!(
            output.status.success(),
            "lpm dev should auto-materialize compat for {} ({})\nstdout:\n{}\nstderr:\n{}",
            case.label,
            case.script,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        let compat_root = project
            .path()
            .join("node_modules")
            .join(".lpm")
            .join("compat")
            .canonicalize()
            .unwrap_or_else(|e| panic!("{} compat root should exist: {e}", case.label));
        let bin_real = project
            .path()
            .join("node_modules")
            .join(".bin")
            .join(case.bin_name)
            .canonicalize()
            .unwrap_or_else(|e| panic!("{} bin shim should resolve: {e}", case.label));
        assert!(
            bin_real.starts_with(&compat_root),
            "{} bin shim should execute from project-local compat, got {}",
            case.label,
            bin_real.display(),
        );
    }
}

#[tokio::test]
async fn dev_auto_compat_relinks_when_install_is_fresh_but_compat_is_missing() {
    let case = FRAMEWORK_BIN_CASES
        .iter()
        .find(|case| case.label == "webpack")
        .expect("webpack fixture should exist");
    let project = project_for_framework_case(case);
    let mock = MockRegistry::start().await;
    mount_framework_case(&mock, case).await;

    let first = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["dev", "--no-open", "--no-dashboard", "--port", "4567"])
        .output()
        .expect("failed to run initial lpm dev");
    assert!(
        first.status.success(),
        "initial lpm dev should create compat\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );

    std::fs::remove_dir_all(
        project
            .path()
            .join("node_modules")
            .join(".lpm")
            .join("compat"),
    )
    .expect("compat root should be removable");

    let second = lpm_with_registry(&project, &mock.url())
        .env("LPM_STORE_VERSION", "v2")
        .args(["dev", "--no-open", "--no-dashboard", "--port", "4567"])
        .output()
        .expect("failed to rerun lpm dev");
    assert!(
        second.status.success(),
        "lpm dev should relink compat even when the install hash is fresh\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
}

fn project_for_framework_case(case: &FrameworkBinCase) -> TempProject {
    TempProject::empty(&format!(
        r#"{{
            "name":"dev-compat-{label}",
            "version":"1.0.0",
            "scripts":{{"dev":{script:?}}},
            "dependencies":{{"{package_name}":"1.0.0"}}
        }}"#,
        label = case.label,
        script = case.script,
        package_name = case.package_name,
    ))
}

async fn mount_framework_case(mock: &MockRegistry, case: &FrameworkBinCase) {
    mock.with_manifest_package(
        serde_json::json!({
            "name": "compat-helper",
            "version": "1.0.0"
        }),
        &[],
    )
    .await;
    mock.with_manifest_package(
        serde_json::json!({
            "name": case.package_name,
            "version": "1.0.0",
            "bin": {
                case.bin_name: "bin/dev-tool.js"
            },
            "dependencies": {
                "compat-helper": "1.0.0"
            }
        }),
        &[("bin/dev-tool.js", framework_bin_script())],
    )
    .await;
}

fn framework_bin_script() -> &'static [u8] {
    br#"#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const project = fs.realpathSync(process.cwd());
const compatRoot = path.join(project, 'node_modules', '.lpm', 'compat') + path.sep;
const ownRealpath = fs.realpathSync(__filename);
if (!ownRealpath.startsWith(compatRoot)) {
  console.error(`entrypoint realpath outside compat: ${ownRealpath}`);
  process.exit(41);
}

const helperPackageJson = require.resolve('compat-helper/package.json');
const helperRealpath = fs.realpathSync(helperPackageJson);
if (!helperRealpath.startsWith(compatRoot)) {
  console.error(`helper realpath outside compat: ${helperRealpath}`);
  process.exit(42);
}

console.log(`compat-ok ${path.basename(process.argv[1])}`);
"#
}

#[cfg(unix)]
#[test]
fn dev_keeps_existing_env_without_reading_a_symlinked_example() {
    let project = TempProject::empty(
        r#"{"name":"existing-env","version":"1.0.0","scripts":{"dev":"node record.js"}}"#,
    );
    project.write_file(".env", "DEV_VALUE=existing\n");
    project.write_file("example-source", "DEV_VALUE=example\n");
    std::os::unix::fs::symlink("example-source", project.path().join(".env.example")).unwrap();
    project.write_file(
        "record.js",
        "require('fs').writeFileSync('value.txt', process.env.DEV_VALUE);",
    );
    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("value.txt"), "existing");
    assert_eq!(project.read_file(".env"), "DEV_VALUE=existing\n");
}

#[test]
fn dev_task_command_overrides_the_package_script_without_package_hooks() {
    let project = TempProject::empty(
        r#"{"name":"dev-task-override","version":"1.0.0","scripts":{"predev":"node package.js","dev":"node package.js","postdev":"node package.js"}}"#,
    );
    project.write_file(
        "lpm.json",
        r#"{"tasks":{"dev":{"command":"node task.js"}}}"#,
    );
    project.write_file(
        "package.js",
        "require('fs').writeFileSync('package.txt', 'ran');",
    );
    project.write_file("task.js", "require('fs').writeFileSync('task.txt', 'ran');");
    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(project.file_exists("task.txt"), "task override did not run");
    assert!(
        !project.file_exists("package.txt"),
        "overridden package command or hook ran"
    );
}

#[test]
fn dev_explicit_env_credentials_survive_filtered_parent_credentials() {
    for config in [
        serde_json::json!({}),
        serde_json::json!({"env":{"dev":"config/custom.env"}}),
        serde_json::json!({"tasks":{"dev":{"env":"staging"}},"environments":{"staging":"config/custom.env"}}),
    ] {
        let project = TempProject::empty(
            r#"{"name":"env-credentials","version":"1.0.0","scripts":{"dev":"node record.js"}}"#,
        );
        project.write_file("lpm.json", &config.to_string());
        for file in [".env", "config/custom.env"] {
            project.write_file(file, "API_TOKEN=project\nORDINARY_VALUE=file\n");
        }
        project.write_file("record.js", "require('fs').writeFileSync('env.json', JSON.stringify({token:process.env.API_TOKEN, ordinary:process.env.ORDINARY_VALUE}));");
        let output = lpm(&project)
            .env("API_TOKEN", "parent")
            .env("ORDINARY_VALUE", "parent")
            .args(["dev", "--no-install", "--no-open"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let actual: serde_json::Value =
            serde_json::from_str(&project.read_file("env.json")).unwrap();
        assert_eq!(
            actual,
            serde_json::json!({"token":"project","ordinary":"parent"}),
            "configuration {config}"
        );
    }
}

#[test]
fn dev_schema_uses_retained_parent_values_before_injecting_defaults() {
    for definition in [
        serde_json::json!({"required":true,"format":"port"}),
        serde_json::json!({"default":"3000","format":"port"}),
    ] {
        let project = TempProject::empty(
            r#"{"name":"inherited-schema","version":"1.0.0","scripts":{"dev":"node record.js"}}"#,
        );
        project.write_file(
            "lpm.json",
            &serde_json::json!({"envSchema":{"vars":{"APPLICATION_PORT":definition}}}).to_string(),
        );
        project.write_file(
            "record.js",
            "require('fs').writeFileSync('value.txt', process.env.APPLICATION_PORT);",
        );
        let output = lpm(&project)
            .env("APPLICATION_PORT", "4000")
            .args(["dev", "--no-install", "--no-open"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(project.read_file("value.txt"), "4000");
    }
}

#[test]
fn dev_undeclared_environment_preserves_the_configured_file_mapping() {
    let project = TempProject::empty(
        r#"{"name":"env-mapping","version":"1.0.0","scripts":{"dev":"node record.js"}}"#,
    );
    project.write_file(
        "lpm.json",
        r#"{"env":{"dev":"config/custom.env"},"environments":{"production":".env.production"}}"#,
    );
    project.write_file("config/custom.env", "MAPPED_VALUE=custom\n");
    project.write_file(
        "record.js",
        "require('fs').writeFileSync('value.txt', process.env.MAPPED_VALUE || 'missing');",
    );
    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("value.txt"), "custom");
}

fn service_env_project(config: serde_json::Value) -> TempProject {
    let project = TempProject::empty(r#"{"name":"service-environment","version":"1.0.0"}"#);
    project.write_file("lpm.json", &config.to_string());
    project.write_file(
        "record.js",
        r#"
const fs = require('fs');
const http = require('http');
fs.writeFileSync('env.json', JSON.stringify(process.env));
const server = http.createServer((req,res)=>res.end('ok'));
server.listen(Number(process.env.PORT), '127.0.0.1', () => setTimeout(()=>server.close(), 500));
"#,
    );
    project
}

#[test]
fn dev_service_variables_cannot_reintroduce_runtime_injection_hooks() {
    let project = service_env_project(
        serde_json::json!({"services":{"worker":{"command":"node record.js","env":{"NODE_OPTIONS":"--require ./hook.cjs","node_options":"blocked","BASH_ENV":"./shell-hook","ORDINARY_VALUE":"service"}}}}),
    );
    project.write_file(
        "hook.cjs",
        "require('fs').writeFileSync('hook.txt', 'ran');",
    );
    project.write_file("shell-hook", "echo injected > shell-hook.txt\n");
    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !project.file_exists("hook.txt"),
        "service NODE_OPTIONS executed a preload"
    );
    let env: serde_json::Value = serde_json::from_str(&project.read_file("env.json")).unwrap();
    assert_eq!(env["ORDINARY_VALUE"], "service");
    for key in ["NODE_OPTIONS", "node_options", "BASH_ENV"] {
        assert!(env.get(key).is_none(), "{key} was injected");
    }
}

#[test]
fn dev_schema_accepts_required_values_from_service_overrides() {
    let project = service_env_project(
        serde_json::json!({"envSchema":{"vars":{"SERVICE_URL":{"required":true,"format":"url"}}},"services":{"worker":{"command":"node record.js","env":{"SERVICE_URL":"https://example.test"}}}}),
    );
    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let env: serde_json::Value = serde_json::from_str(&project.read_file("env.json")).unwrap();
    assert_eq!(env["SERVICE_URL"], "https://example.test");
}

#[test]
fn dev_schema_rejects_invalid_service_overrides_before_spawn() {
    let override_key = if cfg!(windows) {
        "service_url"
    } else {
        "SERVICE_URL"
    };
    let project = service_env_project(
        serde_json::json!({"envSchema":{"vars":{"SERVICE_URL":{"required":true,"format":"url"}}},"services":{"worker":{"command":"node record.js","env":{override_key:"invalid"}}}}),
    );
    project.write_file(".env", "SERVICE_URL=https://example.test\n");
    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "invalid service override was accepted"
    );
    assert!(
        !project.file_exists("env.json"),
        "service started with invalid environment"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("SERVICE_URL"));
    let unchecked = lpm(&project)
        .args([
            "dev",
            "--no-install",
            "--no-open",
            "--no-dashboard",
            "--no-env-check",
        ])
        .output()
        .unwrap();
    assert!(
        unchecked.status.success(),
        "{}",
        String::from_utf8_lossy(&unchecked.stderr)
    );
}

#[cfg(all(unix, debug_assertions))]
#[test]
fn dev_https_passes_a_separate_internal_port_to_vite() {
    use std::os::unix::fs::PermissionsExt;
    // Keep both adjacent ports outside the ephemeral range used by parallel fixtures.
    let start = 20000 + (std::process::id() % 10000) as u16;
    let (listener, internal_listener) = (start..40000)
        .step_by(2)
        .find_map(|port| {
            let frontend = TcpListener::bind(("127.0.0.1", port)).ok()?;
            let internal = TcpListener::bind(("127.0.0.1", port + 1)).ok()?;
            Some((frontend, internal))
        })
        .expect("reserve adjacent dev fixture ports");
    let frontend = listener.local_addr().unwrap().port();
    let project = TempProject::empty(
        r#"{"name":"https-vite","version":"1.0.0","scripts":{"dev":"vite"},"devDependencies":{"vite":"1.0.0"}}"#,
    );
    project.write_file("node_modules/.bin/vite", r#"#!/usr/bin/env node
const fs=require('fs');
const http=require('http');
const flag=process.argv.indexOf('--port');
const port=flag<0 ? Number(process.env.LPM_TEST_DEFAULT_PORT) : Number(process.argv[flag+1]);
fs.writeFileSync('child-port.txt',String(port));
const server=http.createServer((req,res)=>res.end('ok'));
server.listen(port,'127.0.0.1',()=>{console.log(`Local: http://localhost:${port}/`);setTimeout(()=>server.close(),1500);});
"#);
    std::fs::set_permissions(
        project.path().join("node_modules/.bin/vite"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    drop((listener, internal_listener));
    let output = lpm(&project)
        .env("LPM_TEST_DEFAULT_PORT", frontend.to_string())
        .env(
            "LPM_CERT_TEST_TRUST_STORE_DIR",
            project.home().join("test-trust"),
        )
        .env("LPM_CERT_AUDIT_DIR", project.home().join("cert-audit"))
        .args([
            "dev",
            "--https",
            "--yes",
            "--port",
            &frontend.to_string(),
            "--no-install",
            "--no-open",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(project.read_file("child-port.txt"), frontend.to_string());
}

#[cfg(unix)]
#[test]
fn dev_sigterm_stops_predev_and_postdev_process_trees() {
    for phase in ["predev", "postdev"] {
        let project=TempProject::empty(&serde_json::json!({"name":"hook-cleanup","version":"1.0.0","scripts":{"dev":"node -e \"\"",phase:"node hook.js"}}).to_string());
        project.write_file("hook.js", r#"
const fs=require('fs');
const child=require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'});
fs.writeFileSync('hook-pids.json',JSON.stringify([process.pid,child.pid]));
setInterval(()=>{},1000);
"#);
        let mut command = lpm_spawnable(&project);
        command.args(["dev", "--no-install", "--no-open"]);
        let mut child = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let pids = loop {
            if let Ok(data) = std::fs::read_to_string(project.path().join("hook-pids.json")) {
                break serde_json::from_str::<Vec<u32>>(&data).unwrap();
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "dev exited before {phase}"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "{phase} never started"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        // SAFETY: the test owns this live CLI process.
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        let stopped = loop {
            if child.try_wait().unwrap().is_some() && pids.iter().all(|pid| !process_is_alive(*pid))
            {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        if !stopped {
            for pid in &pids {
                // SAFETY: these PIDs belong to the fixture descendants recorded above.
                unsafe {
                    libc::kill(*pid as i32, libc::SIGKILL);
                }
            }
            let _ = child.kill();
        }
        let _ = child.wait();
        assert!(
            stopped,
            "{phase} left a running process after targeted SIGTERM"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dev_prepares_the_selected_runtime_before_dependency_engine_checks() {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    let platform = lpm_runtime::platform::Platform::current().unwrap();
    let top = format!("node-v99.0.0-{}", platform.node_suffix());
    let archive_name = format!("{top}.tar.gz");
    let contents = b"#!/bin/sh\necho v99.0.0\n";
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path(format!("{top}/bin/node")).unwrap();
    header.set_size(contents.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    builder.append(&header, &contents[..]).unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&builder.into_inner().unwrap()).unwrap();
    let archive = encoder.finish().unwrap();
    let digest = format!("{:x}", Sha256::digest(&archive));
    Mock::given(method("GET"))
        .and(path(format!("/v99.0.0/{archive_name}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(500))
                .set_body_bytes(archive),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v99.0.0/SHASUMS256.txt"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("{digest}  {archive_name}\n")),
        )
        .mount(&server)
        .await;
    let project = TempProject::empty(
        r#"{"name":"dev-runtime-order","version":"1.0.0","scripts":{"dev":"node --version"},"engines":{"node":">=99"}}"#,
    );
    project.write_file("lpm.json", r#"{"runtime":{"node":"99.0.0"}}"#);
    let runtime_dir = project.home().join(".lpm/runtimes");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    std::fs::write(
        runtime_dir.join("index-cache.json"),
        r#"[{"version":"v99.0.0","date":"2099-01-01","lts":false}]"#,
    )
    .unwrap();
    let mut command = lpm(&project);
    configure_fake_node(&mut command, &project, "20.0.0");
    let output = command
        .env("LPM_NODE_DIST_BASE_URL", server.uri())
        .args(["dev", "--no-open"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("v99.0.0"));
}

#[test]
fn dev_schema_checks_the_managed_port_that_the_single_server_receives() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let project = TempProject::empty(
        r#"{"name":"single-managed-env","version":"1.0.0","scripts":{"dev":"node record.js"}}"#,
    );
    project.write_file(".env", "port=invalid\n");
    project.write_file(
        "lpm.json",
        r#"{"envSchema":{"vars":{"PORT":{"required":true,"format":"port"}}}}"#,
    );
    project.write_file(
        "record.js",
        "require('fs').writeFileSync('port.txt', process.env.PORT);",
    );
    let output = lpm(&project)
        .env_remove("PORT")
        .args([
            "dev",
            "--no-install",
            "--no-open",
            "--port",
            &port.to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(project.read_file("port.txt"), port.to_string());
}

#[test]
fn dev_restarts_with_the_same_validated_and_filtered_service_environment() {
    let project = service_env_project(serde_json::json!({
        "envSchema":{"vars":{"SERVICE_URL":{"required":true,"format":"url"}}},
        "services":{"worker":{"command":"node record.js","restart":true,"env":{"NODE_OPTIONS":"--require ./hook.cjs","SERVICE_URL":"https://example.test","ORDINARY_VALUE":"service"}}}
    }));
    project.write_file(
        "hook.cjs",
        "require('fs').appendFileSync('hook.txt', 'ran');",
    );
    project.write_file("record.js", r#"
const fs=require('fs');
const http=require('http');
const count=fs.existsSync('env-1.json') ? 2 : 1;
fs.writeFileSync(`env-${count}.json`,JSON.stringify({url:process.env.SERVICE_URL,ordinary:process.env.ORDINARY_VALUE,hook:process.env.NODE_OPTIONS}));
const server=http.createServer((req,res)=>res.end('ok'));
server.listen(Number(process.env.PORT),'127.0.0.1',()=>setTimeout(()=>server.close(()=>process.exit(count===1 ? 1 : 0)),1000));
"#);
    let output = lpm(&project)
        .args(["dev", "--no-install", "--no-open", "--no-dashboard"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for file in ["env-1.json", "env-2.json"] {
        let actual: serde_json::Value = serde_json::from_str(&project.read_file(file)).unwrap();
        assert_eq!(
            actual,
            serde_json::json!({"url":"https://example.test","ordinary":"service"})
        );
    }
    assert!(!project.file_exists("hook.txt"));
}
