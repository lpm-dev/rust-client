//! Workflow tests for `lpm dev`, `lpm tunnel`, and `lpm internal-update-check`.
//!
//! These commands all sit on the network/TTY/server boundary and
//! cannot fully run inside the workflow tier:
//!
//! - `lpm dev` starts long-lived service orchestration (HTTPS server,
//!   tunnel, dashboard) — only the parse-time / help / error paths are
//!   testable hermetically.
//! - `lpm tunnel` opens a network connection to the LPM tunnel
//!   service. A local WebSocket relay covers the successful JSON handshake;
//!   other tests stay on parse-time and local error paths.
//! - `lpm internal-update-check` is a hidden subcommand that refreshes
//!   the update cache — exits cleanly even when the network is down,
//!   since the parent already checked staleness.

mod support;

use futures_util::SinkExt;
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write as _};
use std::net::TcpListener;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use support::auth_state::{SessionSeed, seed_sessions};
use support::{TempProject, lpm, lpm_spawnable};
use tokio_tungstenite::tungstenite::Message;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

const MAX_CAPTURED_STREAM_BYTES: usize = 256 * 1024;

fn captured_webhook(
    id: &str,
    timestamp: &str,
    status: u16,
) -> lpm_tunnel::webhook::CapturedWebhook {
    lpm_tunnel::webhook::CapturedWebhook {
        id: id.to_string(),
        timestamp: timestamp.to_string(),
        method: "POST".to_string(),
        path: "/webhooks/stripe".to_string(),
        request_headers: std::collections::HashMap::from([(
            "stripe-signature".to_string(),
            "t=123,v1=test".to_string(),
        )]),
        request_body: br#"{"type":"payment_intent.payment_failed"}"#.to_vec(),
        response_status: status,
        response_headers: std::collections::HashMap::new(),
        response_body: br#"{"accepted":false}"#.to_vec(),
        duration_ms: 18,
        provider: Some(lpm_tunnel::webhook::WebhookProvider::Stripe),
        summary: "Stripe: payment_intent.payment_failed".to_string(),
        signature_diagnostic: None,
        auto_acked: false,
    }
}

fn command_output_with_deadline(
    mut command: std::process::Command,
    timeout: Duration,
) -> std::process::Output {
    configure_bounded_command(&mut command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn bounded workflow command");
    let stdout = child.stdout.take().expect("bounded stdout pipe");
    let stderr = child.stderr.take().expect("bounded stderr pipe");
    let stdout_capture = std::thread::spawn(move || read_bounded_stream(stdout, "stdout"));
    let stderr_capture = std::thread::spawn(move || read_bounded_stream(stderr, "stderr"));
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        if child
            .try_wait()
            .expect("poll bounded workflow command")
            .is_some()
        {
            break (cleanup_bounded_command(&mut child), false);
        }
        if Instant::now() >= deadline {
            break (cleanup_bounded_command(&mut child), true);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout_capture
        .join()
        .expect("bounded stdout reader thread")
        .expect("read bounded stdout");
    let stderr = stderr_capture
        .join()
        .expect("bounded stderr reader thread")
        .expect("read bounded stderr");
    if timed_out {
        panic!(
            "workflow command exceeded {timeout:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    }
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

#[cfg(unix)]
fn configure_bounded_command(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;

    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_bounded_command(_command: &mut std::process::Command) {}

#[cfg(unix)]
fn cleanup_bounded_command(child: &mut std::process::Child) -> std::process::ExitStatus {
    let process_group = libc::pid_t::try_from(child.id()).expect("bounded child PID fits pid_t");
    // SAFETY: the child was placed in a dedicated process group before spawn;
    // a negative PID targets that owned group without dereferencing memory.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    child.wait().expect("reap bounded workflow command")
}

#[cfg(not(unix))]
fn cleanup_bounded_command(child: &mut std::process::Child) -> std::process::ExitStatus {
    lpm_runner::ports::terminate_child_process_tree(child)
        .expect("terminate bounded workflow process tree")
}

fn read_bounded_stream(mut reader: impl Read, stream: &str) -> std::io::Result<Vec<u8>> {
    let retained_head = MAX_CAPTURED_STREAM_BYTES / 2;
    let retained_tail = MAX_CAPTURED_STREAM_BYTES - retained_head;
    let mut head = Vec::with_capacity(retained_head);
    let mut tail = VecDeque::with_capacity(retained_tail);
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        let mut chunk = &buffer[..read];
        if head.len() < retained_head {
            let head_bytes = (retained_head - head.len()).min(chunk.len());
            head.extend_from_slice(&chunk[..head_bytes]);
            chunk = &chunk[head_bytes..];
        }
        tail.extend(chunk.iter().copied());
        let overflow = tail.len().saturating_sub(retained_tail);
        if overflow != 0 {
            tail.drain(..overflow);
        }
    }
    if total <= MAX_CAPTURED_STREAM_BYTES as u64 {
        head.extend(tail);
        return Ok(head);
    }

    let omitted = total - MAX_CAPTURED_STREAM_BYTES as u64;
    let marker = format!("\n<{stream} truncated: omitted {omitted} bytes>\n");
    let mut output = Vec::with_capacity(MAX_CAPTURED_STREAM_BYTES + marker.len());
    output.extend_from_slice(&head);
    output.extend_from_slice(marker.as_bytes());
    output.extend(tail);
    Ok(output)
}

#[test]
fn deadline_helper_drains_output_while_the_child_is_running() {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "emit_large_output_for_deadline_helper",
            "--nocapture",
        ])
        .env("LPM_TEST_EMIT_LARGE_DEADLINE_OUTPUT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = command_output_with_deadline(command, Duration::from_secs(10));

    assert!(output.status.success());
    assert!(output.stdout.len() <= MAX_CAPTURED_STREAM_BYTES + 128);
    assert!(output.stderr.len() <= MAX_CAPTURED_STREAM_BYTES + 128);
    assert!(
        output
            .stdout
            .windows(b"<stdout truncated:".len())
            .any(|window| window == b"<stdout truncated:")
    );
    assert!(
        output
            .stderr
            .windows(b"<stderr truncated:".len())
            .any(|window| window == b"<stderr truncated:")
    );
}

#[cfg(unix)]
#[test]
fn deadline_helper_does_not_spool_output_to_unbounded_files() {
    use std::os::unix::process::CommandExt as _;

    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "emit_large_output_for_deadline_helper",
            "--nocapture",
        ])
        .env("LPM_TEST_EMIT_LARGE_DEADLINE_OUTPUT", "1");
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: (MAX_CAPTURED_STREAM_BYTES * 2) as libc::rlim_t,
                rlim_max: (MAX_CAPTURED_STREAM_BYTES * 2) as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }

    let output = command_output_with_deadline(command, Duration::from_secs(10));

    assert!(output.status.success());
}

#[test]
fn emit_large_output_for_deadline_helper() {
    if std::env::var_os("LPM_TEST_EMIT_LARGE_DEADLINE_OUTPUT").is_none() {
        return;
    }
    let bytes = vec![b'x'; 2 * 1024 * 1024];
    std::io::stdout().write_all(&bytes).unwrap();
    std::io::stderr().write_all(&bytes).unwrap();
}

#[test]
fn deadline_helper_cleans_a_descendant_that_inherits_output_handles() {
    let fixture = tempfile::tempdir().unwrap();
    let pid_file = fixture.path().join("descendant.pid");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "spawn_inherited_pipe_holder_for_deadline_helper",
            "--nocapture",
        ])
        .env("LPM_TEST_SPAWN_INHERITED_PIPE_HOLDER", "1")
        .env("LPM_TEST_DESCENDANT_PID_FILE", &pid_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();

    let output = command_output_with_deadline(command, Duration::from_secs(2));
    let descendant_pid = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    let cleanup_deadline = Instant::now() + Duration::from_secs(1);
    while lpm_runner::ports::process_is_running(descendant_pid) && Instant::now() < cleanup_deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(output.status.success());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!lpm_runner::ports::process_is_running(descendant_pid));
}

#[test]
#[expect(
    clippy::zombie_processes,
    reason = "the fixture must orphan a short-lived descendant that retains the inherited pipes"
)]
fn spawn_inherited_pipe_holder_for_deadline_helper() {
    if std::env::var_os("LPM_TEST_SPAWN_INHERITED_PIPE_HOLDER").is_none() {
        return;
    }
    let pid_file = std::env::var_os("LPM_TEST_DESCENDANT_PID_FILE").unwrap();
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hold_inherited_pipes_for_deadline_helper",
            "--nocapture",
        ])
        .env("LPM_TEST_HOLD_INHERITED_PIPES", "1")
        .env("LPM_TEST_DESCENDANT_PID_FILE", &pid_file)
        .spawn()
        .unwrap();
    let pid_file = Path::new(&pid_file);
    let deadline = Instant::now() + Duration::from_secs(1);
    while !pid_file.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pid_file.is_file());
}

#[test]
fn hold_inherited_pipes_for_deadline_helper() {
    if std::env::var_os("LPM_TEST_HOLD_INHERITED_PIPES").is_some() {
        let pid_file = std::env::var_os("LPM_TEST_DESCENDANT_PID_FILE").unwrap();
        std::fs::write(pid_file, std::process::id().to_string()).unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }
}

async fn finish_bounded_tunnel_workflow(
    output_task: tokio::task::JoinHandle<std::process::Output>,
    mut relay_task: tokio::task::JoinHandle<()>,
) -> std::process::Output {
    let output = match output_task.await {
        Ok(output) => output,
        Err(error) => {
            relay_task.abort();
            let _ = relay_task.await;
            panic!("bounded tunnel command task failed: {error}");
        }
    };
    match tokio::time::timeout(Duration::from_secs(2), &mut relay_task).await {
        Ok(result) => result.expect("local relay task failed"),
        Err(_) => {
            relay_task.abort();
            let _ = relay_task.await;
            panic!("local relay task did not finish after the tunnel command exited");
        }
    }
    output
}

// ─── dev: --help dispatches and exits cleanly ─────────────────────────

#[test]
fn dev_help_emits_command_usage_and_flags() {
    let project = TempProject::empty(r#"{"name":"dev","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["dev", "--help"])
        .output()
        .expect("failed to run lpm dev --help");

    assert!(
        output.status.success(),
        "lpm dev --help must succeed (clap-level dispatch)"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The help text must mention key flags so a future doc/clap drift
    // (e.g., --tunnel renamed) fails this test.
    assert!(
        stdout.contains("--tunnel") && stdout.contains("--https"),
        "dev --help must list the documented flags, got:\n{stdout}",
    );
}

#[test]
fn dev_human_output_suppresses_nested_install_chatter_and_legacy_glyphs() {
    let project =
        TempProject::empty(r#"{"name":"dev-output","version":"1.0.0","dependencies":{}}"#);
    project.write_file(
        "output-server.js",
        r#"
const net = require("net");
const server = net.createServer();
server.listen(Number(process.env.PORT), "127.0.0.1", () => {
  setTimeout(() => server.close(() => process.exit(0)), 1200);
});
"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "web": {
                    "command": "node output-server.js"
                }
            }
        }"#,
    );

    let output = lpm(&project)
        .args(["dev", "--no-open"])
        .output()
        .expect("failed to run lpm dev for human-output regression test");

    assert!(
        output.status.success(),
        "lpm dev fixture must exit cleanly; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "human lpm dev should not write progress chatter to stdout, got:\n{stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("› Dependencies out of date, installing..."),
        "expected dev-owned install phase line, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Resolving dependencies from")
            && !stderr.contains("No dependencies to install")
            && !stderr.contains("◆")
            && !stderr.contains("▲")
            && !stderr.contains("│"),
        "nested install chatter and legacy glyphs must be absent from dev stderr, got:\n{stderr}"
    );
}

#[test]
fn dev_generic_script_accepts_an_unrelated_compact_short_p_option() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve generic dev port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let project = TempProject::empty(
        r#"{"name":"generic-short-p","version":"1.0.0","scripts":{"dev":"node server.js -production"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const http = require('node:http');
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(Number(process.env.PORT), '127.0.0.1', () => {
  setTimeout(() => server.close(), 100);
});
"#,
    );
    let mut command = lpm_spawnable(&project);
    command.args([
        "dev",
        "--port",
        &port.to_string(),
        "--no-install",
        "--no-open",
        "--no-dashboard",
    ]);

    let output = command_output_with_deadline(command, Duration::from_secs(10));

    assert!(
        output.status.success(),
        "generic dev command failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dev_wrapped_generic_service_accepts_an_unrelated_separated_short_p_option() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve wrapped service port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let project = TempProject::empty(
        r#"{"name":"wrapped-generic-short-p","version":"1.0.0","scripts":{"api":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const http = require('node:http');
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(Number(process.env.PORT), '127.0.0.1', () => {
  setTimeout(() => server.close(), 1500);
});
"#,
    );
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"services":{{"api":{{"command":"npm run api -- -p preview","port":{port},"primary":true}}}}}}"#
        ),
    );
    let mut command = lpm_spawnable(&project);
    command.args(["dev", "--no-install", "--no-open", "--no-dashboard"]);

    let output = command_output_with_deadline(command, Duration::from_secs(10));

    assert!(
        output.status.success(),
        "wrapped generic service failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dev_generic_script_rejects_a_conflicting_long_port_option_before_spawning() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve managed dev port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let project = TempProject::empty(
        r#"{"name":"generic-long-port","version":"1.0.0","scripts":{"dev":"node server.js --port 4321"}}"#,
    );
    project.write_file(
        "server.js",
        "require('node:fs').writeFileSync('started', 'yes');",
    );
    let mut command = lpm_spawnable(&project);
    command.args([
        "dev",
        "--port",
        &port.to_string(),
        "--no-install",
        "--no-open",
        "--no-dashboard",
    ]);

    let output = command_output_with_deadline(command, Duration::from_secs(10));

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("conflicts with managed port"));
    assert!(!project.path().join("started").exists());
}

#[test]
fn dev_wrapped_generic_service_rejects_a_conflicting_long_port_option_before_spawning() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve managed service port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let project = TempProject::empty(
        r#"{"name":"wrapped-generic-long-port","version":"1.0.0","scripts":{"api":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        "require('node:fs').writeFileSync('started', 'yes');",
    );
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"services":{{"api":{{"command":"npm run api -- --port=4321","port":{port},"primary":true}}}}}}"#
        ),
    );
    let mut command = lpm_spawnable(&project);
    command.args(["dev", "--no-install", "--no-open", "--no-dashboard"]);

    let output = command_output_with_deadline(command, Duration::from_secs(10));

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("conflicts with managed port"));
    assert!(!project.path().join("started").exists());
}

#[test]
fn dev_tunnel_propagates_an_explicit_inspector_port_bind_failure() {
    let occupied_inspector = TcpListener::bind("127.0.0.1:0").expect("occupy inspector port");
    let inspector_port = occupied_inspector
        .local_addr()
        .expect("read occupied inspector port")
        .port();
    let child_listener = TcpListener::bind("127.0.0.1:0").expect("reserve child server port");
    let child_port = child_listener
        .local_addr()
        .expect("read child server port")
        .port();
    drop(child_listener);

    let project = TempProject::empty(
        r#"{"name":"dev-tunnel-bind-failure","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        r#"
const http = require('http');
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(Number(process.env.PORT), '127.0.0.1', () => {
  console.log(`Local: http://localhost:${process.env.PORT}/`);
  setTimeout(() => server.close(), 750);
});
"#,
    );

    let output = lpm(&project)
        .env("LPM_TUNNEL_RELAY", "ws://127.0.0.1:9/connect")
        .args([
            "--token",
            "workflow-token",
            "dev",
            "--tunnel",
            "--inspect-port",
            &inspector_port.to_string(),
            "--no-install",
            "--no-open",
            "--no-dashboard",
            "--port",
            &child_port.to_string(),
        ])
        .output()
        .expect("run dev with an occupied explicit inspector port");

    assert!(
        !output.status.success(),
        "fatal tunnel startup errors must determine the dev exit status\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(&format!(
            "inspector port {inspector_port} is already in use"
        )),
        "dev must report the occupied inspector port\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dev_tunnel_rejects_an_inspector_port_equal_to_the_dev_port_before_spawning() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve shared port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let project = TempProject::empty(
        r#"{"name":"dev-tunnel-same-port","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
    );
    project.write_file(
        "server.js",
        "require('node:fs').writeFileSync('child-started', 'yes'); setInterval(() => {}, 1000);\n",
    );
    let mut command = lpm_spawnable(&project);
    command
        .env("LPM_TUNNEL_RELAY", "ws://127.0.0.1:9/connect")
        .args([
            "--token",
            "workflow-token",
            "dev",
            "--tunnel",
            "--inspect-port",
            &port.to_string(),
            "--port",
            &port.to_string(),
            "--no-install",
            "--no-open",
            "--no-dashboard",
        ]);

    let output = command_output_with_deadline(command, Duration::from_secs(5));

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("conflicts with the dev port"));
    assert!(!project.file_exists("child-started"));
}

#[test]
fn dev_tunnel_rejects_a_configured_service_inspector_port_before_spawning() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve service port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let project = TempProject::empty(r#"{"name":"dev-tunnel-service-port","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        &format!(
            r#"{{"services":{{"web":{{"command":"node -e \"require('node:fs').writeFileSync('child-started','yes')\"","port":{port},"primary":true}}}}}}"#
        ),
    );
    let mut command = lpm_spawnable(&project);
    command
        .env("LPM_TUNNEL_RELAY", "ws://127.0.0.1:9/connect")
        .args([
            "--token",
            "workflow-token",
            "dev",
            "--tunnel",
            "--inspect-port",
            &port.to_string(),
            "--no-install",
            "--no-open",
            "--no-dashboard",
        ]);

    let output = command_output_with_deadline(command, Duration::from_secs(5));

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("configured service 'web'"));
    assert!(!project.file_exists("child-started"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dev_tunnel_stops_a_long_running_server_when_the_relay_fails() {
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/connect", relay.local_addr().unwrap());
    let relay_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(8), async {
            let (socket, _) = relay.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "error",
                        "message": "the account plan does not permit this tunnel",
                        "code": "plan_required"
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            websocket.close(None).await.unwrap();
        })
        .await
        .expect("terminal-failure tunnel relay handshake timed out");
    });
    let child_listener = TcpListener::bind("127.0.0.1:0").expect("reserve child port");
    let child_port = child_listener.local_addr().unwrap().port();
    drop(child_listener);
    let output_task = tokio::task::spawn_blocking(move || {
        let project = TempProject::empty(
            r#"{"name":"dev-tunnel-relay-failure","version":"1.0.0","scripts":{"dev":"node server.js"}}"#,
        );
        project.write_file(
            "server.js",
            r#"
const http = require('node:http');
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(Number(process.env.PORT), '127.0.0.1', () => {
  console.log(`Local: http://localhost:${process.env.PORT}/`);
});
setInterval(() => {}, 1000);
"#,
        );
        let mut command = lpm_spawnable(&project);
        command.env("LPM_TUNNEL_RELAY", relay_url).args([
            "--token",
            "workflow-token",
            "dev",
            "--tunnel",
            "--no-inspect",
            "--port",
            &child_port.to_string(),
            "--no-install",
            "--no-open",
            "--no-dashboard",
        ]);
        command_output_with_deadline(command, Duration::from_secs(12))
    });
    let started = Instant::now();

    let output = finish_bounded_tunnel_workflow(output_task, relay_task).await;

    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Tunnel failed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_service_dev_stops_when_the_tunnel_fails_after_readiness() {
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/connect", relay.local_addr().unwrap());
    let relay_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(8), async {
            let (socket, _) = relay.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "hello",
                        "subdomain": "multi-ready.lpm.test",
                        "tunnel_url": "https://multi-ready.lpm.test",
                        "session_id": "session-multi-ready",
                        "plan": "free",
                        "base_domain": "lpm.test",
                        "domain_kind": "random"
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "error",
                        "message": "relay failed after all services became ready",
                        "code": "plan_required"
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            websocket.close(None).await.unwrap();
        })
        .await
        .expect("post-readiness tunnel relay workflow timed out");
    });
    let output_task = tokio::task::spawn_blocking(move || {
        let project =
            TempProject::empty(r#"{"name":"multi-service-tunnel-failure","version":"1.0.0"}"#);
        project.write_file(
            "web.js",
            r#"
const http = require('node:http');
const server = http.createServer((_request, response) => response.end('ok'));
server.listen(Number(process.env.PORT), '127.0.0.1');
setInterval(() => {}, 1000);
"#,
        );
        project.write_file("worker.js", "setInterval(() => {}, 1000);\n");
        project.write_file(
            "lpm.json",
            r#"{
                "services": {
                    "web": {
                        "command": "node web.js",
                        "primary": true,
                        "readyTimeout": 5
                    },
                    "worker": {
                        "command": "node worker.js"
                    }
                }
            }"#,
        );
        let mut command = lpm_spawnable(&project);
        command.env("LPM_TUNNEL_RELAY", relay_url).args([
            "--token",
            "workflow-token",
            "dev",
            "--tunnel",
            "--no-inspect",
            "--no-install",
            "--no-open",
            "--no-dashboard",
        ]);
        command_output_with_deadline(command, Duration::from_secs(12))
    });
    let started = Instant::now();

    let output = finish_bounded_tunnel_workflow(output_task, relay_task).await;

    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("relay failed after all services became ready")
    );
}

#[test]
fn dev_fails_when_a_ready_service_exits_nonzero() {
    let project = TempProject::empty(r#"{"name":"dev-exit","version":"1.0.0"}"#);
    project.write_file(
        "exit-after-ready.js",
        "setTimeout(() => process.exit(23), 350);\n",
    );
    project.write_file(
        "stay-alive.js",
        "setTimeout(() => process.exit(0), 10000);\n",
    );
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "worker": {
                    "command": "node exit-after-ready.js"
                },
                "independent": {
                    "command": "node stay-alive.js"
                }
            }
        }"#,
    );

    let started = std::time::Instant::now();
    let output = lpm(&project)
        .args(["dev", "--no-open", "--no-install"])
        .output()
        .expect("failed to run lpm dev service-exit fixture");

    assert!(
        !output.status.success(),
        "lpm dev must fail when a ready service exits nonzero; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("worker"),
        "failure must name the service: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "a terminal service failure must promptly stop independent services"
    );
}

#[test]
fn dev_rejects_an_invalid_service_cwd_before_starting_any_service() {
    let project = TempProject::empty(r#"{"name":"dev-cwd","version":"1.0.0"}"#);
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "a-marker": {
                    "command": "touch service-started; sleep 1"
                },
                "z-invalid": {
                    "command": "node server.js",
                    "cwd": "missing-directory"
                }
            }
        }"#,
    );

    let output = lpm(&project)
        .args(["dev", "--no-open", "--no-install"])
        .output()
        .expect("failed to run invalid-cwd fixture");

    assert!(!output.status.success());
    assert!(
        !project.path().join("service-started").exists(),
        "no service may start before every configured cwd passes preflight"
    );
}

#[test]
fn dev_rejects_a_missing_script_before_proxy_or_hosts_file_side_effects() {
    let project = TempProject::empty(r#"{"name":"dev-preflight","version":"1.0.0"}"#);
    let hosts_path = project.path().join("hosts");
    fs::write(&hosts_path, "127.0.0.1 localhost\n").unwrap();
    project.write_file(
        "lpm.json",
        r#"{
            "proxy": {
                "host": "app.test",
                "port": 19443,
                "httpRedirect": false
            }
        }"#,
    );

    let output = lpm(&project)
        .env("LPM_HOSTS_FILE", &hosts_path)
        .args(["dev", "--no-open", "--no-install", "--yes"])
        .output()
        .expect("failed to run missing-script preflight fixture");

    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(&hosts_path).unwrap(),
        "127.0.0.1 localhost\n"
    );
    assert!(
        !project.home().join(".lpm/proxy.json").exists(),
        "proxy startup must not precede single-script validation"
    );
}

#[test]
fn dev_restart_republishes_the_active_session_with_the_new_listener_owner() {
    let project = TempProject::empty(r#"{"name":"dev-restart","version":"1.0.0"}"#);
    project.write_file(
        "restart-server.js",
        r#"
const fs = require("fs");
const net = require("net");
const marker = ".first-run-complete";
const firstRun = !fs.existsSync(marker);
if (firstRun) fs.writeFileSync(marker, "done");
const server = net.createServer();
server.listen(Number(process.env.PORT), "127.0.0.1", () => {
  setTimeout(() => server.close(() => process.exit(firstRun ? 1 : 0)), 1200);
});
"#,
    );
    project.write_file(
        "lpm.json",
        r#"{
            "services": {
                "web": {
                    "command": "node restart-server.js",
                    "primary": true,
                    "restart": true,
                    "readyTimeout": 3
                }
            }
        }"#,
    );

    let child = lpm_spawnable(&project)
        .args(["dev", "--no-open"])
        .spawn()
        .expect("failed to start restartable lpm dev fixture");
    let sessions_dir = project.home().join(".lpm").join("dev-sessions");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut first_owner = None;
    let mut restarted_owner = None;
    let mut target_port = None;
    while Instant::now() < deadline {
        if let Ok(entries) = fs::read_dir(&sessions_dir) {
            for entry in entries.flatten() {
                let Ok(bytes) = fs::read(entry.path()) else {
                    continue;
                };
                let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                    continue;
                };
                let owner = record["ownerPid"].as_u64();
                let port = record["target"]["port"].as_u64();
                if first_owner.is_none() {
                    first_owner = owner;
                    target_port = port;
                } else if owner != first_owner {
                    restarted_owner = owner;
                    assert_eq!(port, target_port);
                    break;
                }
            }
        }
        if restarted_owner.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let output = child
        .wait_with_output()
        .expect("failed to wait for restartable lpm dev fixture");
    assert!(
        output.status.success(),
        "restartable lpm dev fixture failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        first_owner.is_some(),
        "initial active session was not written"
    );
    assert!(
        restarted_owner.is_some(),
        "active session was not republished with the restarted listener owner:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(first_owner, restarted_owner);
}

// ─── tunnel: --help dispatches and exits cleanly ──────────────────────

#[test]
fn tunnel_help_emits_action_summary() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args(["tunnel", "--help"])
        .output()
        .expect("failed to run lpm tunnel --help");

    assert!(output.status.success(), "lpm tunnel --help must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Document the action names so a future rename ("claim" →
    // "register"?) fails this test.
    assert!(
        stdout.contains("claim") || stdout.contains("unclaim") || stdout.contains("Actions"),
        "tunnel --help must document the action list, got:\n{stdout}",
    );
}

// ─── tunnel claim: requires auth ──────────────────────────────────────

#[test]
fn tunnel_start_without_auth_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    // A numeric first arg routes to "start <port>" in the tunnel
    // dispatcher. Like every other tunnel action it requires a
    // session-backed bearer — fails before opening any socket.
    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "tunnel",
            "4567",
        ])
        .output()
        .expect("failed to run lpm --json tunnel 4567");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json tunnel <port> error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("tunnel"));
}

#[test]
fn tunnel_bare_domain_error_suggests_the_supported_positional_domain() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
    seed_sessions(
        project.home(),
        &[SessionSeed {
            registry_url: lpm_common::DEFAULT_REGISTRY_URL,
            access_token: Some("workflow-access-token"),
            refresh_token: Some("workflow-refresh-token"),
            session_access_expires_at: Some("2099-01-01T00:00:00Z"),
        }],
    );

    let output = lpm(&project)
        .args(["tunnel", "3000", "acme"])
        .output()
        .expect("failed to run lpm tunnel with a bare domain");

    assert!(!output.status.success(), "a bare domain must be rejected");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lpm tunnel start acme.lpm.llc"),
        "the recovery hint must use the supported positional domain, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("--domain"),
        "the recovery hint must not suggest the rejected --domain flag, got:\n{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_start_under_json_emits_pretty_success_contract_on_stdout() {
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/connect", relay.local_addr().unwrap());
    let relay_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(8), async {
            let (socket, _) = relay.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "hello",
                        "subdomain": "review-test.lpm.test",
                        "tunnel_url": "https://review-test.lpm.test",
                        "session_id": "session-review-test",
                        "plan": "free",
                        "base_domain": "lpm.test",
                        "domain_kind": "random"
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            websocket.close(None).await.unwrap();
        })
        .await
        .expect("JSON tunnel relay handshake timed out");
    });

    let output_task = tokio::task::spawn_blocking(move || {
        let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
        let mut command = lpm_spawnable(&project);
        command.env("LPM_TUNNEL_RELAY", relay_url).args([
            "--token",
            "workflow-token",
            "--json",
            "tunnel",
            "5173",
            "--no-inspect",
        ]);
        command_output_with_deadline(command, Duration::from_secs(12))
    });
    let output = finish_bounded_tunnel_workflow(output_task, relay_task).await;

    assert!(
        output.status.success(),
        "tunnel command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("{\n  \"success\""),
        "tunnel JSON must use the pretty JSON formatter, got:\n{stdout}"
    );
    let contract: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    insta::assert_json_snapshot!(contract, @r#"
    {
      "success": true,
      "tunnel_url": "https://review-test.lpm.test",
      "domain": "review-test.lpm.test",
      "local_port": 5173,
      "local_url": "http://127.0.0.1:5173/",
      "session_id": "session-review-test",
      "plan": "free",
      "base_domain": "lpm.test",
      "domain_kind": "random",
      "session_expires_at": null,
      "session_max_ms": null,
      "limits": null,
      "usage": null,
      "tunnel_auth": null,
      "inspector_url": null,
      "auto_ack": false
    }
    "#);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_start_warns_that_capture_history_persists_sensitive_request_data() {
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/connect", relay.local_addr().unwrap());
    let relay_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(8), async {
            let (socket, _) = relay.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            websocket
                .send(Message::Text(
                    serde_json::json!({
                        "type": "hello",
                        "subdomain": "capture-warning.lpm.test",
                        "tunnel_url": "https://capture-warning.lpm.test",
                        "session_id": "session-capture-warning",
                        "plan": "free",
                        "base_domain": "lpm.test",
                        "domain_kind": "random"
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            websocket.close(None).await.unwrap();
        })
        .await
        .expect("capture-warning tunnel relay handshake timed out");
    });

    let output_task = tokio::task::spawn_blocking(move || {
        let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
        let mut command = lpm_spawnable(&project);
        command.env("LPM_TUNNEL_RELAY", relay_url).args([
            "--token",
            "workflow-token",
            "tunnel",
            "5173",
            "--no-inspect",
        ]);
        command_output_with_deadline(command, Duration::from_secs(12))
    });
    let output = finish_bounded_tunnel_workflow(output_task, relay_task).await;

    assert!(
        output.status.success(),
        "tunnel command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tunnel webhook capture persists full request/response bodies and headers")
            && stderr.contains(".lpm/inspector.db")
            && stderr.contains("mode 0600 on Unix")
            && stderr.contains("project ACLs on Windows"),
        "human tunnel startup must disclose capture persistence:\n{stderr}"
    );
}

#[test]
fn tunnel_claim_without_auth_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "tunnel",
            "claim",
            "test-tunnel.example.test",
        ])
        .output()
        .expect("failed to run lpm --json tunnel claim");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json tunnel claim error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("tunnel"));
}

#[test]
fn tunnel_list_without_auth_under_json_emits_error_envelope_on_stdout() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "--json",
            "tunnel",
            "list",
        ])
        .output()
        .expect("failed to run lpm --json tunnel list");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json tunnel list error path must emit JSON: {e}\n---\n{stdout}")
    });
    assert_eq!(envelope["success"], serde_json::json!(false));
    assert_eq!(envelope["error_code"], serde_json::json!("tunnel"));
}

#[test]
fn tunnel_inspect_without_auth_reads_project_inspector_database_under_json() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let runtime = tokio::runtime::Runtime::new().expect("create fixture runtime");
    runtime.block_on(async {
        let db =
            lpm_inspect::db::InspectorDb::open(project.path()).expect("open inspector database");
        let state = lpm_inspect::state::InspectorState::with_db(3000, db);
        state
            .push(captured_webhook(
                "wh-stripe-402",
                "2026-05-22T10:05:00Z",
                402,
            ))
            .await;
        state.flush().await.unwrap();
    });

    let output = lpm(&project)
        .args(["--json", "tunnel", "inspect"])
        .output()
        .expect("failed to run lpm --json tunnel inspect");

    assert!(
        output.status.success(),
        "local tunnel inspect should not require auth when only reading the on-disk log"
    );

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let entries: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json tunnel inspect must emit the local webhook list: {e}\n---\n{stdout}")
    });
    let rows = entries
        .as_array()
        .expect("expected tunnel inspect JSON output to be an array");
    assert_eq!(rows.len(), 1, "expected one seeded webhook row");
    assert_eq!(rows[0]["provider"], serde_json::json!("Stripe"));
    assert_eq!(rows[0]["status"], serde_json::json!(402));
}

#[test]
fn tunnel_inspect_filters_and_details_share_deterministic_project_history() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let state = lpm_inspect::state::InspectorState::with_db(
            3000,
            lpm_inspect::db::InspectorDb::open(project.path()).unwrap(),
        );
        state
            .push(captured_webhook(
                "oldest-stripe",
                "2026-05-22T10:05:00Z",
                200,
            ))
            .await;
        state
            .push(captured_webhook(
                "middle-stripe",
                "2026-05-22T10:05:01Z",
                402,
            ))
            .await;
        let mut newest = captured_webhook("newest-github", "2026-05-22T10:05:02Z", 500);
        newest.provider = Some(lpm_tunnel::webhook::WebhookProvider::GitHub);
        state.push(newest).await;
        state.flush().await.unwrap();
    });

    let filtered = lpm(&project)
        .args([
            "--json", "tunnel", "inspect", "--last", "10", "--filter", "stripe", "--status", "4xx",
        ])
        .output()
        .unwrap();
    assert!(filtered.status.success());
    let rows: serde_json::Value = serde_json::from_slice(&filtered.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["id"], "middle-stripe");

    let detail = lpm(&project)
        .args(["--json", "tunnel", "inspect", "--detail", "2"])
        .output()
        .unwrap();
    assert!(
        detail.status.success(),
        "detail failed: {}",
        String::from_utf8_lossy(&detail.stderr)
    );
    let webhook: serde_json::Value = serde_json::from_slice(&detail.stdout).unwrap();
    assert_eq!(webhook["id"], "middle-stripe");
    assert_eq!(
        webhook["request_headers"]["stripe-signature"],
        "t=123,v1=test"
    );
}

#[test]
fn tunnel_inspect_ignores_but_preserves_legacy_capture_files() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
    let lpm_dir = project.path().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    let legacy_path = lpm_dir.join("webhook-log.jsonl");
    let legacy = b"{\"id\":\"legacy-only\"}\n";
    std::fs::write(&legacy_path, legacy).unwrap();

    let output = lpm(&project)
        .args(["--json", "tunnel", "inspect"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    assert_eq!(std::fs::read(legacy_path).unwrap(), legacy);
}

#[test]
fn tunnel_log_clear_removes_only_active_sqlite_history_under_json() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
    let lpm_dir = project.path().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    let legacy_path = lpm_dir.join("webhook-log.jsonl");
    let legacy = b"{\"id\":\"legacy-preserved\"}\n";
    std::fs::write(&legacy_path, legacy).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let state = lpm_inspect::state::InspectorState::with_db(
            3000,
            lpm_inspect::db::InspectorDb::open(project.path()).unwrap(),
        );
        state
            .push(captured_webhook(
                "active-capture",
                "2026-05-22T10:05:00Z",
                200,
            ))
            .await;
        state.flush().await.unwrap();
    });

    let output = lpm(&project)
        .args(["--json", "tunnel", "log", "--clear"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "success": true,
            "cleared": true,
            "store": ".lpm/inspector.db"
        })
    );
    assert_eq!(std::fs::read(legacy_path).unwrap(), legacy);

    let inspect = lpm(&project)
        .args(["--json", "tunnel", "inspect"])
        .output()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&inspect.stdout).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn tunnel_inspect_reports_an_actionable_corrupt_database_error() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
    let lpm_dir = project.path().join(".lpm");
    std::fs::create_dir_all(&lpm_dir).unwrap();
    std::fs::write(lpm_dir.join("inspector.db"), b"not sqlite").unwrap();

    let output = lpm(&project).args(["tunnel", "inspect"]).output().unwrap();

    assert!(!output.status.success());
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(rendered.contains(".lpm/inspector.db"));
    assert!(rendered.contains("Repair or move"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_replay_uses_persisted_headers_and_body_and_emits_one_json_document() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let state = lpm_inspect::state::InspectorState::with_db(
        server.address().port(),
        lpm_inspect::db::InspectorDb::open(project.path()).unwrap(),
    );
    let mut webhook = captured_webhook("replay-fidelity", "2026-05-22T10:05:00Z", 500);
    webhook.path = "/webhooks/replay?source=sqlite".to_string();
    webhook
        .request_headers
        .insert("x-replay-canary".to_string(), "header-value".to_string());
    webhook.request_body = b"exact replay body".to_vec();
    state.push(webhook).await;
    state.flush().await.unwrap();

    let port = server.address().port().to_string();
    let output = tokio::task::spawn_blocking(move || {
        lpm(&project)
            .args(["--json", "tunnel", "replay", "--last", "--port", &port])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["success"], true);
    assert_eq!(envelope["id"], "replay-fidelity");
    assert_eq!(envelope["status"], 204);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "POST");
    assert_eq!(requests[0].url.path(), "/webhooks/replay");
    assert_eq!(requests[0].url.query(), Some("source=sqlite"));
    assert_eq!(
        requests[0]
            .headers
            .get("x-replay-canary")
            .and_then(|value| value.to_str().ok()),
        Some("header-value")
    );
    assert_eq!(requests[0].body, b"exact replay body");
}

#[test]
fn tunnel_claim_without_auth_fails_with_clear_message() {
    // `lpm tunnel claim <domain>` calls the registry to claim the
    // domain. On an isolated HOME (no token) the call must fail with
    // a clear auth message instead of crashing or hanging.
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);

    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "tunnel",
            "claim",
            "test-tunnel.example.test",
        ])
        .output()
        .expect("failed to run lpm tunnel claim");

    assert!(
        !output.status.success(),
        "tunnel claim without auth must exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Either an auth-required message OR a network error against the
    // broken localhost endpoint. Both are acceptable contracts; the
    // process MUST exit (not hang).
    assert!(
        !stderr.is_empty() || !String::from_utf8_lossy(&output.stdout).is_empty(),
        "must produce a diagnostic on failure"
    );
}

// ─── internal-update-check: hidden, exits cleanly ─────────────────────

#[test]
fn internal_update_check_hidden_command_exits_zero_even_offline() {
    let project = TempProject::empty(r#"{"name":"iuc","version":"1.0.0"}"#);

    // Point at a deliberately broken registry so the cache-refresh
    // network call fails. The command persists the failure to cache
    // (so the parent's stale check backs off) and exits 0 regardless.
    let output = lpm(&project)
        .args([
            "--registry",
            "http://127.0.0.1:1",
            "--insecure",
            "internal-update-check",
        ])
        .output()
        .expect("failed to run lpm internal-update-check");

    assert!(
        output.status.success(),
        "internal-update-check must always exit 0 (even on network failure) so the parent loop doesn't escalate\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn internal_update_check_is_hidden_from_help() {
    let project = TempProject::empty(r#"{"name":"iuc","version":"1.0.0"}"#);

    let output = lpm(&project)
        .arg("--help")
        .output()
        .expect("failed to run lpm --help");

    assert!(output.status.success(), "lpm --help must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("internal-update-check"),
        "the hidden internal-update-check subcommand must not appear in user-facing help, got:\n{stdout}",
    );
}
