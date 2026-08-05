mod support;

use std::net::{TcpListener, TcpStream};

use support::mock_registry::MockRegistry;
use support::{
    TempProject, configure_fake_node, lpm, lpm_spawnable, lpm_with_registry, write_repeated_file,
};

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
    let child_listener = TcpListener::bind("127.0.0.1:0").expect("reserve child server port");
    let child_port = child_listener
        .local_addr()
        .expect("read child server port")
        .port();
    drop(child_listener);

    let project = TempProject::empty(
        r#"{"name":"dev-frontend-failure","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const http = require('http');
const port = Number(process.env.LPM_TEST_ACTUAL_PORT);
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(port, '127.0.0.1', () => {
  console.log(`Local: http://localhost:${port}/`);
  setTimeout(() => server.close(), 8000);
});
"#,
    );

    let output = lpm(&project)
        .env("LPM_TEST_ACTUAL_PORT", child_port.to_string())
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
    let project = TempProject::empty(
        r#"{
            "name": "dev-readiness-timeout",
            "version": "1.0.0"
        }"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "db": {
                    "command": "node slow-service.js",
                    "readyUrl": "http://127.0.0.1:0/health",
                    "readyTimeout": 1
                },
                "api": {
                    "command": "node dependent.js",
                    "dependsOn": ["db"]
                }
            }
        }"#,
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
            && stderr.contains("timed out waiting for http://127.0.0.1:0/health (1s)"),
        "error must identify the service and readiness target\nstderr:\n{stderr}"
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
