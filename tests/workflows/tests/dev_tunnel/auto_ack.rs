use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_ack_is_on_disk_before_provider_receives_success() {
    let project = TempProject::empty(r#"{"name":"tunnel","version":"1.0.0"}"#);
    let project_path = project.path().to_path_buf();
    let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = local.local_addr().unwrap().port().to_string();
    let local_task = tokio::spawn(async move {
        let (socket, _) = local.accept().await.unwrap();
        drop(socket);
    });
    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/connect", relay.local_addr().unwrap());
    let relay_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(12), async move {
            let (socket, _) = relay.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
            websocket.send(Message::Text(serde_json::json!({
                "type":"hello", "protocol":4, "transport_seq":1, "transport_ack_nonce":"00000000-0000-4000-8000-000000000001", "subdomain":"capture.lpm.test", "tunnel_url":"https://capture.lpm.test",
                "session_id":"durable-session", "plan":"pro", "base_domain":"lpm.test", "domain_kind":"random"
            }).to_string())).await.unwrap();
            await_fixture_ready(&mut websocket).await;
            websocket.send(Message::Text(serde_json::json!({
                "type":"http_request", "transport_seq":2, "transport_ack_nonce":"00000000-0000-4000-8000-000000000002", "id":"durable-auto-ack", "method":"POST", "url":"/webhook",
                "headers":{"content-type":"application/json"}, "body":"e30="
            }).to_string())).await.unwrap();
            let mut request_acked = false;
            loop {
                let message = websocket.next().await.unwrap().unwrap();
                let Message::Text(text) = message else { continue };
                let response: serde_json::Value = serde_json::from_str(&text).unwrap();
                if response["type"] == "transport_ack" {
                    assert_eq!(response["transport_seq"], 2);
                    assert_eq!(response["transport_ack_nonce"], "00000000-0000-4000-8000-000000000002");
                    request_acked = true;
                    continue;
                }
                if response["id"] != "durable-auto-ack" { continue }
                assert!(request_acked, "request receipt precedes the provider response");
                assert_eq!(response["status"], 200);
                // Read through a new connection before shutdown can flush queued captures.
                let db = lpm_inspect::db::InspectorDb::open(&project_path).unwrap();
                let captured = db.get_webhook("durable-auto-ack").await.unwrap().expect("success requires a persisted capture");
                assert!(captured.auto_acked);
                assert_eq!(captured.request_body, b"{}");
                break;
            }
            websocket.close(None).await.unwrap();
        }).await.expect("durable capture relay timed out");
    });
    let output_task = tokio::task::spawn_blocking(move || {
        let mut command = lpm_spawnable(&project);
        command.env("LPM_TUNNEL_RELAY", relay_url).args([
            "--token",
            "workflow-token",
            "--json",
            "tunnel",
            &local_port,
            "--no-inspect",
            "--auto-ack",
        ]);
        command_output_with_deadline(command, Duration::from_secs(16))
    });
    let output = finish_bounded_tunnel_workflow(output_task, relay_task).await;
    local_task.await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
