//! Hold release-time responses until the client fills its four request slots.
//! Wall-clock start offsets measure runner scheduling, not client concurrency.

use crate::support::{TempProject, lpm_spawnable};
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

pub async fn check_outdated_hydration(project: &TempProject, count: usize) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (requests, mut pending) = mpsc::unbounded_channel();
    let mut server = JoinSet::new();
    server.spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let requests = requests.clone();
            connections.spawn(async move {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                let name = line.split_whitespace().nth(1).unwrap().trim_start_matches('/').to_string();
                let mut full = false;
                loop {
                    line.clear();
                    reader.read_line(&mut line).await.unwrap();
                    if line == "\r\n" || line.is_empty() { break; }
                    full |= line.trim().eq_ignore_ascii_case("accept: application/json");
                }
                let mut body = serde_json::json!({
                    "name": name,
                    "dist-tags": { "latest": "1.1.0" },
                    "versions": {
                        "1.0.0": { "name": name, "version": "1.0.0" },
                        "1.1.0": { "name": name, "version": "1.1.0" }
                    }
                });
                if full {
                    let (release, wait) = oneshot::channel();
                    requests.send(release).unwrap();
                    if wait.await.is_err() { return; }
                    body["time"] = serde_json::json!({
                        "1.0.0": "2025-01-01T00:00:00.000Z",
                        "1.1.0": "2025-01-01T00:00:00.000Z"
                    });
                }
                let body = body.to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                reader.get_mut().write_all(response.as_bytes()).await.unwrap();
            });
        }
    });

    let mut command = lpm_spawnable(project);
    command
        .args([
            "--registry",
            &url,
            "--insecure",
            "--json",
            "global",
            "list",
            "--outdated",
        ])
        .env("LPM_INTERNAL_TEST_NPM_REGISTRY_URL", &url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut command = tokio::process::Command::from(command);
    command.kill_on_drop(true);
    let child = command.spawn().unwrap();
    for _ in 0..count / 4 {
        let mut wave = Vec::new();
        for _ in 0..4 {
            wave.push(
                tokio::time::timeout(Duration::from_secs(20), pending.recv())
                    .await
                    .expect("client must fill four slots before responses are released")
                    .expect("registry request channel"),
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(250), pending.recv())
                .await
                .is_err(),
            "client exceeded four outstanding release-time requests"
        );
        for release in wave {
            release.send(()).unwrap();
        }
    }
    tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("global outdated completion")
        .unwrap()
}
