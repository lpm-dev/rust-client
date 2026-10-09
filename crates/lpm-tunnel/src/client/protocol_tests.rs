use super::*;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tokio_tungstenite::WebSocketStream;

#[test]
fn slow_failed_startup_never_resets_the_retry_budget() {
    assert!(!healthy_tunnel_attempt(None));
    assert!(!healthy_tunnel_attempt(Some(Duration::from_secs(59))));
    assert!(healthy_tunnel_attempt(Some(Duration::from_secs(60))));
}

#[tokio::test]
#[expect(
    clippy::result_large_err,
    reason = "The WebSocket handshake callback requires an unboxed error response"
)]
async fn rejected_token_refresh_time_does_not_reset_retry_history() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut options = TunnelOptions::new("test-token".into(), 3000);
    options.no_pin = true;
    options.relay_url = format!("ws://{}/connect", listener.local_addr().unwrap());
    let shutdown = tokio_util::sync::CancellationToken::new();
    options.shutdown = Some(shutdown.clone());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let barrier = Arc::clone(&entered);
    let resume = Arc::clone(&release);
    options.token_provider = Some(TunnelTokenProvider::new(
        || Box::pin(async { Ok("test-token".into()) }),
        move || {
            let barrier = Arc::clone(&barrier);
            let resume = Arc::clone(&resume);
            Box::pin(async move {
                barrier.notify_one();
                resume.notified().await;
                Err(LpmError::Network("refresh unavailable".into()))
            })
        },
    ));
    let (socket_tx, socket_rx) = tokio::sync::oneshot::channel();
    let relay = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = tokio_tungstenite::accept_hdr_async(
            stream,
            |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
             _: tokio_tungstenite::tungstenite::handshake::server::Response| {
                Err(tokio_tungstenite::tungstenite::http::Response::builder()
                    .status(503)
                    .body(Some("unavailable".into()))
                    .unwrap())
            },
        )
        .await;
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(receipt(hello(), 1).to_string()))
            .await
            .unwrap();
        loop {
            let message = socket.next().await.unwrap().unwrap();
            if let Message::Text(text) = message
                && serde_json::from_str::<Value>(&text).unwrap()["type"] == "client_ready"
            {
                break;
            }
        }
        socket_tx.send(socket).unwrap();
    });
    let (retry_tx, mut retries) = tokio::sync::mpsc::unbounded_channel();
    let client = tokio::spawn(async move {
        connect_with_usage_fallible(
            &options,
            |_| Ok(()),
            |message| {
                retry_tx.send(message.to_owned()).unwrap();
            },
            |_, _| {},
        )
        .await
    });
    let first = timeout(Duration::from_secs(2), retries.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(first.contains("(unavailable") || first.contains("retrying"));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;
    tokio::time::resume();
    let mut socket = timeout(Duration::from_secs(2), socket_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(57)).await;
    tokio::time::resume();
    socket
        .send(Message::Text(
            receipt(
                json!({"type":"error", "message":"credential expired", "code":"auth_failed"}),
                2,
            )
            .to_string(),
        ))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::resume();
    release.notify_one();
    let second = timeout(Duration::from_secs(2), retries.recv())
        .await
        .unwrap()
        .unwrap();
    shutdown.cancel();
    client.await.unwrap().unwrap();
    relay.await.unwrap();
    let seconds: u64 = second
        .split("retrying in ")
        .nth(1)
        .unwrap()
        .split('s')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (4..=6).contains(&seconds),
        "refresh time reset retry history: {second}"
    );
}

#[expect(
    clippy::result_large_err,
    reason = "The WebSocket handshake callback requires an unboxed error response"
)]
async fn pending_credentials_drop(rejected: bool, cancel: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let dropped = tokio_util::sync::CancellationToken::new();
    let entered = Arc::new(tokio::sync::Notify::new());
    let mut options = TunnelOptions::new("test-token".into(), 3000);
    options.no_pin = true;
    options.relay_url = format!("ws://{}/connect", listener.local_addr().unwrap());
    options.shutdown = Some(shutdown.clone());
    let pending_provider = {
        let entered = Arc::clone(&entered);
        let dropped = dropped.clone();
        move || {
            let entered = Arc::clone(&entered);
            let guard = dropped.clone().drop_guard();
            Box::pin(async move {
                let _guard = guard;
                entered.notify_one();
                std::future::pending().await
            }) as TunnelTokenFuture
        }
    };
    options.token_provider = Some(if rejected {
        TunnelTokenProvider::new(
            || Box::pin(async { Ok("test-token".into()) }),
            pending_provider,
        )
    } else {
        TunnelTokenProvider::new(pending_provider, || {
            Box::pin(async { panic!("unexpected refresh") })
        })
    });
    let relay = tokio::spawn(async move {
        if rejected {
            let (stream, _) = listener.accept().await.unwrap();
            let result = tokio_tungstenite::accept_hdr_async(
                stream,
                |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 _: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    Err(tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(401)
                        .body(Some("invalid token".into()))
                        .unwrap())
                },
            )
            .await;
            assert!(result.is_err());
        }
    });
    let retry_observed = Arc::new(Mutex::new(String::new()));
    let observed = Arc::clone(&retry_observed);
    let retry_shutdown = shutdown.clone();
    let mut client = tokio::spawn(async move {
        if rejected {
            connect_with_usage_fallible(
                &options,
                |_| panic!("unexpected connection"),
                |message| {
                    *observed.lock().unwrap() = message.to_owned();
                    retry_shutdown.cancel();
                },
                |_, _| {},
            )
            .await
            .map_err(TunnelConnectError::from_token_provider)
        } else {
            try_connect(&options, &|_| panic!("unexpected connection"), &|_, _| {}).await
        }
    });
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    if cancel {
        shutdown.cancel();
    } else {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(20)).await;
    }
    let result = timeout(Duration::from_millis(200), &mut client).await;
    if result.is_err() {
        client.abort();
    }
    let result = result
        .expect("credential provider exceeded its deadline")
        .unwrap();
    if cancel || rejected {
        result.unwrap();
    } else {
        let error = result.unwrap_err();
        assert_eq!(error.retry_class, RetryClass::Transient);
        assert!(error.to_string().contains("Tunnel credential"));
    }
    if rejected && !cancel {
        assert!(
            retry_observed
                .lock()
                .unwrap()
                .contains("Tunnel credential refresh timed out")
        );
    }
    assert!(dropped.is_cancelled());
    relay.await.unwrap();
}

#[tokio::test]
async fn shutdown_drops_pending_initial_credentials() {
    pending_credentials_drop(false, true).await;
}

#[tokio::test]
async fn shutdown_drops_pending_rejected_credentials() {
    pending_credentials_drop(true, true).await;
}

#[tokio::test]
async fn pending_initial_credentials_expire_after_twenty_seconds() {
    pending_credentials_drop(false, false).await;
}

#[tokio::test]
async fn pending_rejected_credentials_expire_after_twenty_seconds() {
    pending_credentials_drop(true, false).await;
}

#[tokio::test]
async fn silent_upgrade_and_hello_have_deadlines_and_cooperative_shutdown() {
    for hello in [false, true] {
        for cancel in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let entered = Arc::new(tokio::sync::Notify::new());
            let shutdown = tokio_util::sync::CancellationToken::new();
            let mut options = TunnelOptions::new("test-token".into(), 3000);
            options.no_pin = true;
            options.relay_url = format!("ws://{}/connect", listener.local_addr().unwrap());
            options.shutdown = Some(shutdown.clone());
            let barrier = Arc::clone(&entered);
            let relay = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                if hello {
                    let _socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                    barrier.notify_one();
                    std::future::pending::<()>().await;
                } else {
                    let mut input = [0; 1024];
                    assert!(stream.read(&mut input).await.unwrap() > 0);
                    barrier.notify_one();
                    std::future::pending::<()>().await;
                }
            });
            let mut client = tokio::spawn(async move {
                try_connect(
                    &options,
                    &|_| panic!("silent relay published readiness"),
                    &|_, _| {},
                )
                .await
            });
            timeout(Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            if cancel {
                shutdown.cancel();
            }
            let result = timeout(
                Duration::from_secs(if cancel { 1 } else { 16 }),
                &mut client,
            )
            .await
            .unwrap()
            .unwrap();
            relay.abort();
            if cancel {
                result.unwrap();
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.retry_class, RetryClass::Transient);
                assert!(error.to_string().contains(if hello {
                    "Tunnel hello timed out"
                } else {
                    "Tunnel connection timed out"
                }));
            }
        }
    }
}

struct RawRelay {
    socket: WebSocketStream<TcpStream>,
    client: JoinHandle<Result<(), TunnelConnectError>>,
    connected: Arc<AtomicUsize>,
    captures: tokio::sync::mpsc::Receiver<CapturedWebhookEvent>,
    sequence: u64,
}

impl Drop for RawRelay {
    fn drop(&mut self) {
        self.client.abort();
    }
}

fn receipt(mut value: Value, sequence: u64) -> Value {
    value["transport_seq"] = json!(sequence);
    value["transport_ack_nonce"] = json!(format!("00000000-0000-4000-8000-{sequence:012x}"));
    value
}

fn hello() -> Value {
    json!({"type":"hello", "protocol":4, "subdomain":"raw.localhost", "tunnel_url":"http://raw.localhost", "session_id":"raw-session"})
}

impl RawRelay {
    async fn new(port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut options = TunnelOptions::new("test-token".into(), port);
        options.relay_url = format!("ws://{}/connect", listener.local_addr().unwrap());
        options.no_pin = true;
        let (capture_tx, captures) = tokio::sync::mpsc::channel(1);
        options.webhook_tx = Some(capture_tx);
        let connected = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&connected);
        let client = tokio::spawn(async move {
            try_connect(
                &options,
                &|_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                &|_, _| {},
            )
            .await
        });
        let (socket, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        Self {
            socket,
            client,
            connected,
            captures,
            sequence: 0,
        }
    }

    async fn next(&mut self) -> Value {
        loop {
            let message = timeout(Duration::from_secs(2), self.socket.next())
                .await
                .expect("missing raw relay response")
                .unwrap()
                .unwrap();
            if let Message::Text(text) = message {
                let value: Value = serde_json::from_str(&text).unwrap();
                if value["type"] != "ping" {
                    return value;
                }
            }
        }
    }

    async fn send(&mut self, value: Value) {
        self.sequence += 1;
        let value = receipt(value, self.sequence);
        self.socket
            .send(Message::Text(value.to_string()))
            .await
            .unwrap();
        assert_eq!(
            self.next().await,
            json!({"type":"transport_ack", "transport_seq":self.sequence, "transport_ack_nonce":value["transport_ack_nonce"]})
        );
    }

    async fn ready(&mut self) {
        self.send(hello()).await;
        assert_eq!(self.next().await, json!({"type":"client_ready"}));
        assert_eq!(self.connected.load(Ordering::SeqCst), 1);
    }

    async fn permanent_failure(&mut self) {
        let result = timeout(Duration::from_secs(2), &mut self.client)
            .await
            .expect("invalid frame must terminate connection")
            .unwrap();
        assert_eq!(result.unwrap_err().retry_class, RetryClass::Permanent);
        while let Ok(Some(Ok(Message::Text(text)))) =
            timeout(Duration::from_millis(100), self.socket.next()).await
        {
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_ne!(value["type"], "transport_ack");
            assert_ne!(value["type"], "client_ready");
        }
    }
}

#[tokio::test]
async fn invalid_raw_hello_never_acknowledges_or_publishes_readiness() {
    for mutation in [
        "missing-protocol",
        "old-protocol",
        "missing-receipt",
        "short-nonce",
        "skipped-sequence",
    ] {
        let mut relay = RawRelay::new(3000).await;
        let mut value = receipt(hello(), 1);
        match mutation {
            "missing-protocol" => {
                value.as_object_mut().unwrap().remove("protocol");
            }
            "old-protocol" => value["protocol"] = json!(3),
            "missing-receipt" => {
                value.as_object_mut().unwrap().remove("transport_seq");
            }
            "short-nonce" => value["transport_ack_nonce"] = json!("short"),
            "skipped-sequence" => value["transport_seq"] = json!(2),
            _ => unreachable!(),
        }
        relay
            .socket
            .send(Message::Text(value.to_string()))
            .await
            .unwrap();
        relay.permanent_failure().await;
        assert_eq!(relay.connected.load(Ordering::SeqCst), 0, "{mutation}");
    }
}

#[tokio::test]
async fn invalid_raw_active_receipts_terminate_without_acknowledgement() {
    for mutation in [
        "missing-sequence",
        "missing-nonce",
        "string-sequence",
        "overflow-sequence",
        "replay",
        "skip",
        "short-nonce",
        "invalid-character",
        "misplaced-hyphen",
        "invalid-json",
    ] {
        let mut relay = RawRelay::new(3000).await;
        relay.ready().await;
        let mut value = receipt(json!({"type":"pong"}), 2);
        match mutation {
            "missing-sequence" => {
                value.as_object_mut().unwrap().remove("transport_seq");
            }
            "missing-nonce" => {
                value.as_object_mut().unwrap().remove("transport_ack_nonce");
            }
            "string-sequence" => value["transport_seq"] = json!("2"),
            "overflow-sequence" => value["transport_seq"] = json!(u64::MAX),
            "replay" => value["transport_seq"] = json!(1),
            "skip" => value["transport_seq"] = json!(3),
            "short-nonce" => value["transport_ack_nonce"] = json!("a"),
            "invalid-character" => {
                value["transport_ack_nonce"] = json!("z0000000-0000-4000-8000-000000000002")
            }
            "misplaced-hyphen" => {
                value["transport_ack_nonce"] = json!("000000000000-4000-8000-00000000000-")
            }
            "invalid-json" => {}
            _ => unreachable!(),
        }
        let text = if mutation == "invalid-json" {
            "{".into()
        } else if mutation == "overflow-sequence" {
            value
                .to_string()
                .replace(&u64::MAX.to_string(), "18446744073709551616")
        } else {
            value.to_string()
        };
        relay.socket.send(Message::Text(text)).await.unwrap();
        relay.permanent_failure().await;
    }
}

#[tokio::test]
async fn protocol_four_public_websocket_rejection_never_connects_to_origin() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut relay = RawRelay::new(origin.local_addr().unwrap().port()).await;
    relay.ready().await;
    relay
        .send(json!({"type":"ws_upgrade", "id":"browser", "url":"/socket", "headers":{}}))
        .await;
    assert_eq!(
        relay.next().await,
        json!({"type":"ws_reject", "id":"browser", "error":"Public WebSockets are unavailable"})
    );
    assert!(
        timeout(Duration::from_millis(100), origin.accept())
            .await
            .is_err()
    );
}

async fn event_origin(two_chunks: bool, finish: bool) -> (u16, JoinHandle<usize>) {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: 1\n\n\r\n").await.unwrap();
        if two_chunks {
            socket.write_all(b"9\r\ndata: 2\n\n\r\n").await.unwrap();
        }
        if finish {
            socket.write_all(b"0\r\n\r\n").await.unwrap();
            return 0;
        }
        socket.read(&mut request).await.unwrap()
    });
    (port, task)
}

async fn start_stream(relay: &mut RawRelay) {
    relay.ready().await;
    relay.send(json!({"type":"http_request", "id":"sse", "method":"GET", "url":"/events", "headers":{}, "body":""})).await;
    let start = relay.next().await;
    assert_eq!(start["type"], "http_response_start");
    assert_eq!(start["status"], 200);
    assert!(
        timeout(Duration::from_millis(50), relay.socket.next())
            .await
            .is_err(),
        "body must wait for visitor demand"
    );
    relay
        .send(json!({"type":"http_response_pull", "id":"sse", "seq":1}))
        .await;
    let chunk = relay.next().await;
    assert_eq!(chunk["type"], "http_response_chunk");
    assert_eq!(chunk["seq"], 1);
    assert_eq!(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            chunk["body"].as_str().unwrap()
        )
        .unwrap(),
        b"data: 1\n\n"
    );
    assert!(
        timeout(Duration::from_millis(50), relay.socket.next())
            .await
            .is_err(),
        "second chunk needs another credit"
    );
}

#[tokio::test]
async fn raw_stream_cancellation_and_invalid_pull_sequences_close_the_origin() {
    for sequence in [None, Some(1), Some(3)] {
        let (port, origin) = event_origin(true, false).await;
        let mut relay = RawRelay::new(port).await;
        start_stream(&mut relay).await;
        match sequence {
            Some(seq) => {
                relay
                    .send(json!({"type":"http_response_pull", "id":"sse", "seq":seq}))
                    .await
            }
            None => relay.send(json!({"type":"http_cancel", "id":"sse"})).await,
        }
        assert_eq!(
            relay.next().await,
            json!({"type":"http_cancelled", "id":"sse"})
        );
        assert_eq!(
            timeout(Duration::from_secs(2), origin)
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn raw_stream_requires_each_credit_and_finishes_at_the_next_sequence() {
    let (port, origin) = event_origin(true, true).await;
    let mut relay = RawRelay::new(port).await;
    start_stream(&mut relay).await;
    relay
        .send(json!({"type":"http_response_pull", "id":"sse", "seq":2}))
        .await;
    let chunk = relay.next().await;
    assert_eq!(chunk["type"], "http_response_chunk");
    assert_eq!(chunk["seq"], 2);
    assert_eq!(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            chunk["body"].as_str().unwrap()
        )
        .unwrap(),
        b"data: 2\n\n"
    );
    assert!(
        timeout(Duration::from_millis(50), relay.socket.next())
            .await
            .is_err()
    );
    relay
        .send(json!({"type":"http_response_pull", "id":"sse", "seq":3}))
        .await;
    assert_eq!(
        relay.next().await,
        json!({"type":"http_response_end", "id":"sse", "failed":false, "seq":3})
    );
    assert_eq!(
        timeout(Duration::from_secs(2), origin)
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn raw_sse_survives_thirty_seconds_and_stops_at_thirty_minutes_with_partial_capture() {
    let (port, origin) = event_origin(false, false).await;
    let mut relay = RawRelay::new(port).await;
    start_stream(&mut relay).await;
    relay
        .send(json!({"type":"http_response_pull", "id":"sse", "seq":2}))
        .await;
    let mut elapsed = 0;
    for seconds in [16, 15].into_iter().chain(std::iter::repeat_n(29, 60)) {
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::time::resume();
        elapsed += seconds;
        relay.send(json!({"type":"pong"})).await;
        if elapsed == 31 {
            assert!(!origin.is_finished());
            assert!(!relay.client.is_finished());
            assert!(
                timeout(Duration::from_millis(50), relay.socket.next())
                    .await
                    .is_err()
            );
        }
    }
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    assert_eq!(
        relay.next().await,
        json!({"type":"http_response_end", "id":"sse", "failed":true, "seq":2})
    );
    assert_eq!(
        timeout(Duration::from_secs(2), origin)
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let capture = timeout(Duration::from_secs(2), relay.captures.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(capture.webhook.response_body_incomplete);
    assert_eq!(capture.webhook.response_status, 200);
    assert_eq!(capture.webhook.response_body, b"data: 1\n\n");
}
