use super::*;

async fn failed_forward(
    webhook_tx: Option<tokio::sync::mpsc::Sender<CapturedWebhookEvent>>,
) -> ClientMessage {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let request = ServerMessage::HttpRequest {
        id: "needs-replay".into(),
        method: "POST".into(),
        url: "/webhook".into(),
        headers: HashMap::new(),
        body: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0, 1, 2, 127, 128, 255],
        ),
    };
    let (response, _) = forward_http_request(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, port),
        request,
        true,
        webhook_tx,
        Arc::new(tokio::sync::Semaphore::new(HTTP_RESPONSE_MEMORY_PERMITS)),
        None,
        None,
    )
    .await;
    response
}

#[tokio::test]
async fn auto_ack_without_capture_returns_retryable_error() {
    assert_eq!(extract_response_data(&failed_forward(None).await).0, 503);
}

#[tokio::test]
async fn auto_ack_with_closed_capture_returns_retryable_error() {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    drop(rx);
    assert_eq!(
        extract_response_data(&failed_forward(Some(tx)).await).0,
        503
    );
}

#[tokio::test]
async fn auto_ack_requires_persistence_not_channel_delivery() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let consumer = tokio::spawn(async move {
        drop(rx.recv().await.unwrap());
    });
    assert_eq!(
        extract_response_data(&failed_forward(Some(tx)).await).0,
        503
    );
    consumer.await.unwrap();
}

#[tokio::test]
async fn auto_ack_waits_for_successful_persistence() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedWebhookEvent>(1);
    let forward = tokio::spawn(failed_forward(Some(tx)));
    let event = rx.recv().await.unwrap();
    assert!(event.requires_persistence());
    assert_eq!(event.webhook.request_body, [0, 1, 2, 127, 128, 255]);
    assert!(!forward.is_finished());
    event.complete_persistence(Ok(()));
    assert_eq!(extract_response_data(&forward.await.unwrap()).0, 200);
}

#[tokio::test]
async fn auto_ack_persistence_failure_returns_retryable_error() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedWebhookEvent>(1);
    let consumer = tokio::spawn(async move {
        rx.recv()
            .await
            .unwrap()
            .complete_persistence(Err("disk full".into()));
    });
    assert_eq!(
        extract_response_data(&failed_forward(Some(tx)).await).0,
        503
    );
    consumer.await.unwrap();
}

#[tokio::test]
async fn auto_ack_with_full_capture_queue_returns_retryable_error() {
    let (tx, _rx) = tokio::sync::mpsc::channel::<CapturedWebhookEvent>(1);
    let _reserved = tx.reserve().await.unwrap();
    assert_eq!(
        extract_response_data(&failed_forward(Some(tx.clone())).await).0,
        503
    );
}

#[tokio::test(start_paused = true)]
async fn auto_ack_persistence_deadline_returns_retryable_error() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedWebhookEvent>(1);
    let forward = tokio::spawn(failed_forward(Some(tx)));
    let event = rx.recv().await.unwrap();
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    assert_eq!(extract_response_data(&forward.await.unwrap()).0, 503);
    event.complete_persistence(Ok(()));
}

#[test]
fn taking_request_body_releases_the_encoded_allocation_and_preserves_binary_bytes() {
    let mut request = ServerMessage::HttpRequest {
        id: "binary".into(),
        method: "POST".into(),
        url: "/".into(),
        headers: HashMap::new(),
        body: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0, 1, 2, 127, 128, 255],
        ),
    };
    assert_eq!(
        take_request_body(&mut request).unwrap().as_ref(),
        [0, 1, 2, 127, 128, 255]
    );
    let ServerMessage::HttpRequest { body, .. } = request else {
        panic!("expected HTTP")
    };
    assert_eq!(body.capacity(), 0);
}

#[tokio::test]
async fn successful_binary_upload_preserves_origin_and_capture_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut headers = Vec::with_capacity(1024);
        while !headers.ends_with(b"\r\n\r\n") {
            assert!(headers.len() < 8192);
            headers.push(socket.read_u8().await.unwrap());
        }
        let mut body = [0; 6];
        socket.read_exact(&mut body).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        body
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let request = ServerMessage::HttpRequest {
        id: "binary-success".into(),
        method: "POST".into(),
        url: "/webhook".into(),
        headers: HashMap::new(),
        body: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0, 1, 2, 127, 128, 255],
        ),
    };
    let (response, _) = forward_http_request(
        reqwest::Client::builder().no_proxy().build().unwrap(),
        lpm_common::LocalTarget::loopback(lpm_common::LocalScheme::Http, port),
        request,
        false,
        Some(tx),
        Arc::new(tokio::sync::Semaphore::new(HTTP_RESPONSE_MEMORY_PERMITS)),
        None,
        None,
    )
    .await;
    assert_eq!(extract_response_data(&response).0, 200);
    assert_eq!(server.await.unwrap(), [0, 1, 2, 127, 128, 255]);
    let capture = rx.recv().await.unwrap();
    assert_eq!(capture.webhook.request_body, [0, 1, 2, 127, 128, 255]);
    assert_eq!(capture.webhook.response_body, b"ok");
}
